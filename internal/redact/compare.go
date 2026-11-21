package redact

import (
	"regexp"
	"strings"
)

// credentialWords are the key words of the password and generic rules.
const credentialWords = `(?:` + anyValueWords + `|` + shapedValueWords + `)`

// compareDetectors mask a value compared with a credential key where the
// vendored generic rule cannot see it (#190): after "!=" or "!==", which its
// operator list lacks, and after a subscript (os.environ["API_KEY"] ==),
// whose "]" it does not allow. Like the generic rule's comparedWord
// exemption, the value needs the generic shape, so a plain word compared
// (secret !== "undefined") stays readable.
var compareDetectors = []patternDetector{
	{
		label: genericLabel,
		re:    regexp.MustCompile(`(?i)` + credentialWords + `[A-Za-z0-9_.-]*[ \t]*!==?[ \t]*` + quotedValue),
		valid: genericShape, when: notEqualGate, skip: harmlessComparedName,
	},
	{
		label: genericLabel,
		re:    regexp.MustCompile(subscriptPath(credentialWords) + `[ \t]*(?:!==?|===?)[ \t]*` + quotedValue),
		valid: genericShape, when: subscriptGate, skip: harmlessKey,
	},
}

var notEqualGate = regexp.MustCompile(`!=`)

// harmlessComparedName judges the key before "!=": the name the match
// starts with, as harmlessKey judges a subscript's.
func harmlessComparedName(prefix string) bool {
	end := strings.IndexFunc(prefix, func(r rune) bool { return !isNameChar(r) })
	if end < 0 {
		end = len(prefix)
	}
	return harmlessName(prefix[:end])
}

func isNameChar(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune("_.-", r)
}
