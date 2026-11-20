package redact

import (
	"regexp"
	"strings"
)

// bareVerdict is what the password detector does with an unquoted value.
type bareVerdict int

const (
	maskValue     bareVerdict = iota // a secret written out, or a shape no rule below knows
	keepValue                        // not an assignment at all: "$PWD:/src" expands a shell variable before a path
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
	case strings.HasPrefix(key, "$") && operator(key) == ":" && strings.HasPrefix(value, "/"):
		return keepValue
	case lookupExpr(value, after):
		return keepLookup
	case nullWords[strings.ToLower(value)], !notPlaceholder(value), callExpr(value, after),
		referencePath(value), typeAnnotation(key, value), measureNumber(key, value):
		return keepReference
	}
	return maskValue
}

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
// decrypt("x"), os.environ["X"]. A password holding a bracket (t8w(!d%5r)
// has nothing after it that closes one, so it is masked.
func callExpr(value, after string) bool {
	m := exprRe.FindStringSubmatch(value)
	if m == nil {
		return false
	}
	closer := ")"
	if m[2] == "[" {
		closer = "]"
	}
	return strings.Count(m[2]+m[3], m[2]) > strings.Count(m[3], closer) && strings.Contains(after, closer)
}

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

// referenceWordRe: a word that config objects and credential fields carry.
var referenceWordRe = regexp.MustCompile(`(?i)env|conf|cfg|setting|secret|pass|pwd|key|token|auth|cred|param|option|opts|args|props|vault`)

// referencePath reports a dotted path that reads config or a credential
// field: process.env.SECRET_KEY, cfg.Secret, user.password. A dotted
// value with none of those words (correct.horse.battery) may be a
// passphrase and is masked.
func referencePath(value string) bool {
	return referencePathRe.MatchString(value) && referenceWordRe.MatchString(value)
}

// typeNames are the type names a key is annotated with: password: string.
var typeNames = map[string]bool{
	"string": true, "str": true, "number": true, "int": true, "integer": true,
	"long": true, "float": true, "double": true, "bool": true, "boolean": true,
	"bytes": true, "byte": true, "char": true, "any": true, "unknown": true,
	"object": true, "secretstr": true, "secretbytes": true, "optional": true, "list": true,
}

// typeAnnotation reports a type name after a ":" (password: string;,
// password: str = ..., f(password: str), password: Optional[str]). After
// "=" the same word may be a password.
func typeAnnotation(key, value string) bool {
	if operator(key) != ":" {
		return false
	}
	base, _, _ := strings.Cut(strings.TrimRight(value, "[]?!)"), "[")
	return typeNames[strings.ToLower(base)]
}

var numberRe = regexp.MustCompile(`^[0-9][0-9_]*(?:\.[0-9]+)?$`)

// measureKeyRe is a key that measures a password or secret rather than
// holding one: PASSWORD_MIN_LENGTH, passwordHashRounds, SECRET_TTL.
var measureKeyRe = regexp.MustCompile(`(?i)(?:passw(?:or)?d|passphrase|pwd|secret)[A-Za-z0-9_.-]*?` +
	`(?:len|length|size|min|max|minimum|maximum|count|rounds|cost|iterations?|attempts|retries|tries|ttl|timeout|` +
	`expiry|expires|expiration|age|days|hours|minutes|seconds|interval|lifetime|duration|version|level|limit|history|` +
	`strength|bits|bytes|chars|characters|digits)s?$`)

// measureNumber reports a number under a key that measures the password.
// A number under any other key (PIN = 1234, DB_PASSWORD=123456) is masked.
func measureNumber(key, value string) bool {
	name := strings.TrimRight(key, " \t:=>\"'`]")
	return numberRe.MatchString(value) && measureKeyRe.MatchString(name)
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
