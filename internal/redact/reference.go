package redact

import (
	"regexp"
	"strings"
)

// bareVerdict is what the password detector does with an unquoted value.
type bareVerdict int

const (
	maskValue     bareVerdict = iota // a secret written out, or a shape no rule below knows
	keepValue                        // not an assignment at all: "$PWD:/src" expands a shell variable before a path, no blank between
	keepReference                    // code that stands for a value; the literals after it are masked
	keepLookup                       // a lookup whose first literal names what it reads
)

// judgeBare decides on an unquoted password value from the text before it
// (key and operator), the value and the rest of its line, of which it reads
// at most closeWindow bytes. It keeps only shapes that are code, not a
// secret written out (#71): null and boolean words, a number under a key
// that measures the password, a type annotation, a reference such as $VAR,
// ${VAR} or cfg.Secret, and a call or a subscript the line goes on to
// close. Anything else is masked, since masking too much is safer than too
// little. A kept value can still be followed by a literal on its line (None
// or "x", get("X", "default"), str = "x"): the detector masks those
// (tailLiterals).
func judgeBare(key, value, after string) bareVerdict {
	switch {
	case strings.HasPrefix(key, "$") && strings.HasSuffix(key, ":") && shellPathRe.MatchString(value):
		return keepValue
	case lookupExpr(value, after):
		return keepLookup
	case nullWords[strings.ToLower(value)], !notPlaceholder(value), callExpr(value, after),
		referencePath(value), typeAnnotation(key, value), measureNumber(key, value):
		return keepReference
	}
	return maskValue
}

// shellPathRe is the path after a shell variable: "$PWD:/src".
var shellPathRe = regexp.MustCompile(`^/[A-Za-z0-9_./-]*$`)

// nullWords are values that hold no secret in any language.
var nullWords = map[string]bool{
	"none": true, "null": true, "nil": true, "undefined": true, "nullptr": true,
	"true": true, "false": true,
}

// operator returns the assignment operator that ends key: ":", "=", ":="
// or "=>".
func operator(key string) string {
	key = strings.TrimRight(key, " \t")
	for _, op := range []string{":=", "=>", "=", ":"} {
		if strings.HasSuffix(key, op) {
			return op
		}
	}
	return ""
}

// closeWindow bounds how far after a value judgeBare looks for the bracket
// that closes a call, so a line of many values costs a fixed amount each.
const closeWindow = 256

// exprRe splits a call or subscript into its callee path, its bracket and
// what follows up to the end of the bare value.
var exprRe = regexp.MustCompile(`^([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)([(\[])(.*)$`)

// callExpr reports a call or subscript left open at the end of the value
// and closed later on the line: GenerateFromPassword(pw, cost),
// decrypt("x"), os.environ["X"]. The value must end at a comma or a quote
// (the next argument or a literal one), and its arguments so far must be
// names without digits ([]byte(pw). A password holding a bracket
// (t8w(!d%5r, real(PW99 + x)) does not fit that shape, so it is masked.
func callExpr(value, after string) bool {
	m := exprRe.FindStringSubmatch(value)
	if m == nil || !callArgsRe.MatchString(m[3]) || after == "" || !strings.ContainsRune(",\"'`", rune(after[0])) {
		return false
	}
	closer := ")"
	if m[2] == "[" {
		closer = "]"
	}
	return strings.Count(m[2]+m[3], m[2]) > strings.Count(m[3], closer) && strings.Contains(after, closer)
}

// callArgsRe is what may follow a call's bracket within the value.
var callArgsRe = regexp.MustCompile(`^(?:[A-Za-z_$.()]|\[\])*$`)

// lookupExpr reports a call of a lookup function, or a subscript, that ends
// where a quoted argument starts: os.environ[, os.getenv(, config.get(,
// ENV.fetch(. That first literal is the name of what it reads.
func lookupExpr(value, after string) bool {
	m := exprRe.FindStringSubmatch(value)
	if m == nil || m[3] != "" || !callExpr(value, after) {
		return false
	}
	name := strings.ToLower(m[1][strings.LastIndexByte(m[1], '.')+1:])
	return m[2] == "[" || strings.Contains(name, "env") || strings.HasPrefix(name, "get") || lookupNames[name]
}

var lookupNames = map[string]bool{
	"fetch": true, "lookup": true, "config": true, "setting": true, "settings": true,
	"param": true, "params": true, "option": true, "property": true, "value": true,
}

// referencePathRe is a dotted path of names: letters, "_" and "$", each
// short enough to be a name rather than part of a token. A digit anywhere
// makes it read like a password.
var referencePathRe = regexp.MustCompile(`^[A-Za-z_$]{1,32}(?:\.[A-Za-z_$]{1,32})+$`)

// referenceReceivers are the config and environment objects values are read
// from, as the whole first segment of a path, spelled exactly so: a
// capitalized word (This.Is.Sparta) starts a passphrase, not code. Words a
// passphrase starts with (self, this, app, my) are left out, so
// self.password and this.is.sparta are masked (auditor A1 on #71).
var referenceReceivers = map[string]bool{
	"cfg": true, "config": true, "conf": true, "settings": true, "os": true,
	"process": true, "env": true, "environ": true, "options": true, "opts": true,
	"params": true, "args": true, "request": true, "props": true,
}

// referencePath reports a dotted path read from a known receiver:
// process.env.SECRET_KEY, cfg.Secret. Any other dotted value
// (monkey.island.sunset, user.password, self.password) may be a passphrase
// and is masked.
func referencePath(value string) bool {
	first, _, _ := strings.Cut(value, ".")
	return referencePathRe.MatchString(value) && referenceReceivers[first]
}

// typeNames are the type names a key is annotated with: password: string.
var typeNames = map[string]bool{
	"string": true, "str": true, "number": true, "int": true, "integer": true,
	"long": true, "float": true, "double": true, "bool": true, "boolean": true,
	"bytes": true, "byte": true, "char": true, "any": true, "unknown": true,
	"object": true, "secretstr": true, "secretbytes": true, "optional": true, "list": true,
}

// typeAnnotation reports a type name after a ":" (password: string;,
// password: str = ..., f(password: str), password: Optional[str]). Text in
// brackets must be a type name too. After "=" the same word may be a
// password.
func typeAnnotation(key, value string) bool {
	if operator(key) != ":" {
		return false
	}
	v := strings.TrimSuffix(strings.TrimRight(value, "?!)"), "[]")
	base, inner, generic := strings.Cut(v, "[")
	if generic {
		inner, closed := strings.CutSuffix(inner, "]")
		if !closed || !typeNames[strings.ToLower(inner)] {
			return false
		}
	}
	return typeNames[strings.ToLower(base)]
}

var numberRe = regexp.MustCompile(`^[0-9][0-9_]*(?:\.[0-9]+)?$`)

// measureWords name what a key measures about a password or secret.
var measureWords = map[string]bool{
	"len": true, "length": true, "size": true, "min": true, "max": true, "minimum": true,
	"maximum": true, "count": true, "rounds": true, "cost": true, "iteration": true,
	"iterations": true, "attempts": true, "retries": true, "tries": true, "ttl": true,
	"timeout": true, "expiry": true, "expires": true, "expiration": true, "age": true,
	"days": true, "hours": true, "minutes": true, "seconds": true, "interval": true,
	"lifetime": true, "duration": true, "version": true, "level": true, "limit": true,
	"history": true, "strength": true, "bits": true, "bytes": true, "chars": true,
	"characters": true, "digits": true,
}

// measureNumber reports a number under a key whose last word measures the
// password: PASSWORD_MIN_LENGTH, passwordHashRounds, SECRET_TTL. A number
// under any other key (PIN = 1234, DB_PASSWORD=123456, PASSWORD_ADMIN,
// SECRET_MESSAGE) is masked.
func measureNumber(key, value string) bool {
	name := strings.TrimRight(key, " \t:=>\"'`]")
	return numberRe.MatchString(value) && measureWords[strings.ToLower(lastWord(name))]
}

// lastWord returns the last word of an identifier: after the last "_", "."
// or "-", or the last change from a lowercase letter to an uppercase one.
func lastWord(name string) string {
	for i := len(name) - 1; i > 0; i-- {
		c, prev := name[i], name[i-1]
		if strings.IndexByte("_.-", prev) >= 0 {
			return name[i:]
		}
		if c >= 'A' && c <= 'Z' && prev >= 'a' && prev <= 'z' {
			return name[i:]
		}
	}
	return name
}

// closesString reports a value that ends at a quote closing the string it
// sits in ("DB_PASSWORD=$DB_PASSWORD" -v x): the quote opens no literal, so
// the text after it is not read as one. A value ending in an opening
// bracket, an operator or a separator is followed by a literal instead.
func closesString(padded string, start, end int) bool {
	if !isQuote(padded[end]) {
		return false
	}
	return !strings.ContainsRune("([{,+=:", rune(padded[end-1]))
}

func isQuote(c byte) bool { return c == '"' || c == '\'' || c == '`' }

// skipLiteral returns the end of the literal starting at i, the name a
// lookup reads, or i when no closed literal starts there.
func skipLiteral(padded string, i int) int {
	if !isQuote(padded[i]) {
		return i
	}
	n := closingQuote(padded, i)
	if n < 0 {
		return i
	}
	return n + 1
}

// closingQuote returns the index of the quote that closes the literal
// opened at i, on the same line, or -1.
func closingQuote(padded string, i int) int {
	for j := i + 1; j < len(padded); j++ {
		switch c := padded[j]; {
		case c == '\n':
			return -1
		case c == '\\' && padded[j+1] != '\n':
			j++ // padded ends in a newline, so j+1 is in range
		case c == padded[i]:
			return j
		}
	}
	return -1
}

// tailLiterals returns, in text offsets, the contents of the literals from
// padded[from] to the end of its line, and that line end. It stops at a
// comment ("#", "//"). A "\"" or "`" left open masks the rest of the line,
// which may be a string that goes on; a "'" left open, or one inside a word
// (don't), is an apostrophe and masks nothing. Once one "'" is left open no
// later one can close, so each byte is read at most twice.
func tailLiterals(padded string, from int, label string) ([]span, int) {
	lineEnd := from + strings.IndexByte(padded[from:], '\n')
	var out []span
	singleOpen := false
	for i := from; i < lineEnd; i++ {
		c := padded[i]
		if c == '#' || (c == '/' && padded[i+1] == '/') {
			break
		}
		if !isQuote(c) || (c == '\'' && (singleOpen || apostrophe(padded, i))) {
			continue
		}
		j := closingQuote(padded, i)
		switch {
		case j > i+1:
			out = append(out, span{start: i, end: j - 1, label: label})
		case j < 0 && c != '\'':
			return append(out, span{start: i, end: lineEnd - 1, label: label}), lineEnd
		case j < 0:
			singleOpen = true
			continue
		}
		i = j
	}
	return out, lineEnd
}

// apostrophe reports a "'" between letters after a word of three letters or
// more (don't, isn't), not after a string prefix (f'x', rb'x').
func apostrophe(padded string, i int) bool {
	if padded[i] != '\'' || !isLetter(padded[i+1]) {
		return false
	}
	n := 0
	for n < 3 && i-n-1 >= 0 && isLetter(padded[i-n-1]) {
		n++
	}
	return n == 3
}

func isLetter(c byte) bool { return (c|0x20) >= 'a' && (c|0x20) <= 'z' }
