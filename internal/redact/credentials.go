package redact

import (
	"regexp"
	"strings"
)

// Labels of the detectors that match on a key name alone; a rule that knows
// the secret's own format names a shared span instead (see labelRank).
const (
	passwordLabel = "SECRET_PASSWORD"
	genericLabel  = "SECRET_GENERIC_API_KEY"
)

// Characters that end an unquoted value in code or config files.
const valueStop = "\\s\"'`,;"

// credentialDetectors cover credentials the gitleaks rules miss because they
// have no fixed format: they are recognized by where they sit, not by shape.
var credentialDetectors = append([]patternDetector{
	{
		// scheme://[user]:password@host. The password runs to the last "@"
		// before a space or quote, so a raw "@" or "/" inside it cannot end
		// the match early and leave the rest visible; that may also mask the
		// host, which is the safe side.
		label: "SECRET_URL_PASSWORD",
		re:    regexp.MustCompile("[A-Za-z][A-Za-z0-9+.-]*://[^\\s:@/\"'`<>]*:([^\\s\"'`<>]+)@"),
		when:  regexp.MustCompile("://"),
	},
	{
		// key = value, key: value, key := value, key => value, with the value
		// in double, single or back quotes, or bare (.env, YAML, properties,
		// JSON, code). The key may close a subscript (x['secret'] = v).
		// Only the value is masked; the key stays readable.
		label: passwordLabel,
		re: regexp.MustCompile(`(?i)[A-Za-z0-9_.-]*(?:passw(?:or)?d|passphrase|pwd|secret)[A-Za-z0-9_.-]*["']?\]?[ \t]*(?::=|=>|=|:)[ \t]*` +
			"(?:\"([^\"\\r\\n]*)\"|'([^'\\r\\n]*)'|`([^`\\r\\n]*)`|([^=" + valueStop + "][^" + valueStop + "]*))"),
		valid: notPlaceholder,
		when:  regexp.MustCompile(`(?i)passw|passphrase|pwd|secret`),
	},
	{
		// A bare AWS secret access key has no prefix, so a 40-character
		// base64 run is masked only when an access key id shares the input.
		label: "SECRET_AWS_SECRET_KEY",
		re:    regexp.MustCompile(`[^A-Za-z0-9/+]([A-Za-z0-9/+]{40})[^A-Za-z0-9/+]`),
		valid: mixedCase,
		when:  regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}`),
	},
}, subscriptDetectors...)

// callRe matches a value that is a function call in code, not a literal
// password: getPassword() or os.Getenv( (the bare value stops at the quote
// of the argument). A password of that exact shape is not masked.
var callRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*\(\)?$`)

// notPlaceholder rejects values that only point at a password: ${VAR}, $VAR,
// {{ var }}, <your-password>, %s and function calls. Anything else is masked,
// including words like changeme: masking too much is safer than too little.
func notPlaceholder(v string) bool {
	switch {
	case strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}"),
		strings.HasPrefix(v, "{{") && strings.HasSuffix(v, "}}"),
		strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">"),
		v == "%s", v == "%v",
		callRe.MatchString(v):
		return false
	}
	return !envRefRe.MatchString(v)
}

var envRefRe = regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`)

// mixedCase keeps lowercase hex digests (git and SHA-1 hashes) unmasked; a
// random AWS secret key holds both cases.
func mixedCase(v string) bool {
	return strings.ContainsAny(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") &&
		strings.ContainsAny(v, "abcdefghijklmnopqrstuvwxyz")
}

// labelRank orders the labels of overlapping spans: the merged span takes the
// highest. A rule that knows the secret's format beats one that only saw a
// key name, any secret beats PII, and anything beats the unlabelled sweep.
func labelRank(label string) int {
	switch {
	case label == "":
		return 0
	case strings.HasPrefix(label, "PII_"):
		return 1
	case label == genericLabel, label == passwordLabel:
		return 2
	}
	return 3
}

// wordValueRe is the gitleaks allowlist for generic-api-key values: letters,
// "_", "." and "-" with no digit make a word, not a key.
var wordValueRe = regexp.MustCompile(`^[A-Za-z_.-]+$`)

// comparedWord reports a generic-api-key value that is a word compared with
// "==" or "===", as in key === "constructor": code testing a name, not a key
// being set (#167). Only the generic rule is exempt, and only for a
// comparison: an assigned value, or a compared one with a digit or any other
// character, is still masked.
func (r secretRule) comparedWord(text string, start, end int) bool {
	if r.label != genericLabel || !wordValueRe.MatchString(text[start:end]) {
		return false
	}
	// The rule allows at most 5 quotes or blanks before the value, so this
	// trim stops within a few bytes.
	return strings.HasSuffix(strings.TrimRight(text[:start], " \t\"'`"), "==")
}
