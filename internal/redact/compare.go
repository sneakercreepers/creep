package redact

import (
	"regexp"
	"strings"
)

// credentialWords are the key words of the password and generic rules.
const credentialWords = `(?:` + anyValueWords + `|` + shapedValueWords + `)`

// Comparison operators: the vendored generic rule reads "==" and "===", so
// only the password words, which it does not mask at any length, need them
// here. "<>" is SQL's and Basic's, "≠" Julia's, ".equals(" Java's and C#'s.
const (
	notEqualOps = `(?:!==?|<>|≠|\.equals(?:IgnoreCase)?\()`
	compareOps  = `(?:===?|!==?|<>|≠|\.equals(?:IgnoreCase)?\()`
)

// compareDetectors mask a value compared with a credential key where the
// vendored rules cannot see it (#190): after "!=", "!==", "<>", "≠" or
// ".equals(", which the generic rule's operator list lacks; after a lookup
// (os.environ["API_KEY"] ==, os.getenv("TOKEN") !=), whose "]" or ")" it
// does not allow; and a short value under a password word, which the
// generic rule's 10-byte floor lets through (password == "hunter2!"). The
// key may close a shell quote ("$API_TOKEN" != "…"). Like the generic
// rule's comparedWord exemption, a plain word compared (secret !==
// "undefined") stays readable; under the generic words the value also
// needs the generic shape.
var compareDetectors = []patternDetector{
	{
		label: passwordLabel, re: regexp.MustCompile(comparedName(anyValueWords, compareOps) + quotedValue),
		valid: comparedSecret, when: compareGate, skip: harmlessComparedName,
	},
	{
		label: genericLabel, re: regexp.MustCompile(comparedName(shapedValueWords, notEqualOps) + quotedValue),
		valid: genericShape, when: compareGate, skip: harmlessComparedName,
	},
	{
		label: passwordLabel, re: regexp.MustCompile(lookupPath(anyValueWords) + `[ \t]*` + compareOps + `[ \t]*` + quotedValue),
		valid: comparedSecret, when: lookupGate, skip: harmlessLookup,
	},
	{
		label: genericLabel, re: regexp.MustCompile(lookupPath(credentialWords) + `[ \t]*` + compareOps + `[ \t]*` + quotedValue),
		valid: genericShape, when: lookupGate, skip: harmlessLookup,
	},
}

// comparedName matches a name holding one of words, an optional closing
// "}" and quote ("${API_TOKEN}" in a shell test) and one of ops.
func comparedName(words, ops string) string {
	return `(?i)` + words + `[A-Za-z0-9_.-]*\}?["'` + "`" + `]?[ \t]*` + ops + `[ \t]*`
}

// lookupPath matches the subscripts of subscriptKey, or a call whose only
// argument is a quoted key (os.getenv("API_KEY"), cfg.get('token')).
func lookupPath(words string) string {
	call := `\([ \t]*["'` + "`" + `][A-Za-z0-9_.-]*` + words + `[A-Za-z0-9_.-]*["'` + "`" + `][ \t]*\)`
	return `(?i)(?:` + strings.TrimPrefix(subscriptPath(words), "(?i)") + `|` + call + `)`
}

var (
	compareGate = regexp.MustCompile(`(?i)[!=]=|<>|≠|\.equals`)
	lookupGate  = regexp.MustCompile(`(?i)[\[(][ \t]*[:"'` + "`" + `]?[A-Za-z0-9_.-]*` + credentialWords)
	equalsRe    = regexp.MustCompile(`(?i)\.equals(?:ignorecase)?$`)
)

// comparedSecret is the password rule's value check for a compared value:
// anything but a placeholder or a plain word.
func comparedSecret(v string) bool {
	return notPlaceholder(v) && !wordValueRe.MatchString(v)
}

// harmlessComparedName judges the key before the operator: the name the
// match starts with, as harmlessKey judges a subscript's.
func harmlessComparedName(prefix string) bool {
	end := strings.IndexFunc(prefix, func(r rune) bool { return !isNameChar(r) })
	if end < 0 {
		end = len(prefix)
	}
	return harmlessName(equalsRe.ReplaceAllString(prefix[:end], ""))
}

// harmlessLookup judges a call's quoted argument as harmlessKey judges a
// subscript's key.
func harmlessLookup(prefix string) bool {
	return harmlessKey(strings.NewReplacer("(", "[", ")", "]").Replace(prefix))
}

func isNameChar(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune("_.-", r)
}
