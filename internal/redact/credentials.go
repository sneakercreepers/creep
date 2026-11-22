package redact

import (
	"regexp"
	"slices"
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

// Pieces of the XML detectors. An element's text may sit on its own line
// or in a CDATA section; a password attribute's key and value may come in
// either order, with other attributes and line breaks between them. Every
// repeat before a line break is bounded, so a match stays within
// chunkOverlap (TestChunkOverlapBound).
const (
	keyNameWord      = `(?:passw(?:or)?d|passphrase|pwd|secret)`
	xmlTagName       = `[A-Za-z0-9_.:-]{0,64}`
	passwordNameAttr = `(?:key|name)[ \t]{0,8}=[ \t]{0,8}["'][^"'\r\n<>]{0,64}` + keyNameWord + `[^"'\r\n<>]{0,64}["']`
	xmlText          = `[ \t\r\n]{0,32}(?:<!\[CDATA\[([^\r\n]{1,256}?)\]\]>|([^<\r\n]{1,256}?))[ \t\r\n]{0,32}</`
	xmlAttrValue     = `(?:"([^"\r\n]{0,256})"|'([^'\r\n]{0,256})')`
	xmlAttrsBetween  = `[ \t\r\n]{1,32}(?:[A-Za-z0-9_.:-]{1,64}[ \t]{0,8}=[ \t]{0,8}(?:"[^"\r\n]{0,64}"|'[^'\r\n]{0,64}')[ \t\r\n]{1,32}){0,3}?`
)

// credentialDetectors cover credentials the gitleaks rules miss because they
// have no fixed format: they are recognized by where they sit, not by shape.
var credentialDetectors = slices.Concat([]patternDetector{
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
		// JSON, code). The key may close a subscript (x['secret'] = v), and
		// a leading "$" stays in the key so judgeBare can tell a shell
		// expansion ("$PWD:/src") from an assignment. Only the value is
		// masked; the key stays readable. An unquoted value that is code,
		// not a secret written out, is kept, and the literals after it on
		// its line are masked instead (judgeBare).
		label: passwordLabel,
		re: regexp.MustCompile(`(?i)\$?[A-Za-z0-9_.-]*(?:passw(?:or)?d|passphrase|pwd|secret)[A-Za-z0-9_.-]*["']?\]?[ \t]*(?::=|=>|=|:)[ \t]*` +
			"(?:\"([^\"\\r\\n]*)\"|'([^'\\r\\n]*)'|`([^`\\r\\n]*)`|([^=" + valueStop + "][^" + valueStop + "]*))"),
		valid: notPlaceholder,
		bare:  judgeBare,
		when:  regexp.MustCompile(`(?i)passw|passphrase|pwd|secret`),
	},
	{
		// An XML element named like a password (Maven settings.xml,
		// <password>..</password>): the text up to the closing tag.
		label: passwordLabel,
		re:    regexp.MustCompile(`(?i)<` + xmlTagName + keyNameWord + xmlTagName + `(?:[ \t][^<>\r\n]{0,64})?>` + xmlText),
		valid: notPlaceholder,
		when:  regexp.MustCompile(`(?i)passw|passphrase|pwd|secret`),
	},
	{
		// An XML element whose key or name attribute names a password
		// (Java <entry key="password">..</entry>, Spring
		// <property name="password">..</property>).
		label: passwordLabel,
		re:    regexp.MustCompile(`(?i)<[A-Za-z0-9_.:-]{1,64}[ \t\r\n][^<>]{0,64}?\b` + passwordNameAttr + `[^<>]{0,64}>` + xmlText),
		valid: notPlaceholder,
		when:  regexp.MustCompile(`(?i)passw|passphrase|pwd|secret`),
	},
	{
		// A key or name attribute that names a password and a value
		// attribute, in either order, other attributes and line breaks
		// between them (.NET <add key="DbPassword" value=".."/>, Spring
		// <property name="password" value=".."/>).
		label: passwordLabel,
		re: regexp.MustCompile(`(?i)\b` + passwordNameAttr + xmlAttrsBetween + `value[ \t]{0,8}=[ \t]{0,8}` + xmlAttrValue +
			`|\bvalue[ \t]{0,8}=[ \t]{0,8}` + xmlAttrValue + xmlAttrsBetween + passwordNameAttr),
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
}, subscriptDetectors, compareDetectors)

// callRe matches a value that is a call without arguments in code, not a
// literal password: getPassword(). A call with arguments is judged by
// callExpr. A password of that exact shape is not masked.
var callRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*\(\)$`)

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

// referenceWord reports a generic-api-key value that is a dotted path read
// from a known receiver, as in process.env.SECRET_KEY or cfg.Secret: code
// reading a key, not a key (#71). The value must also
// be a word in the gitleaks allowlist sense, so a token with a digit is
// still masked, whatever its shape.
func (r secretRule) referenceWord(value string) bool {
	return r.label == genericLabel && wordValueRe.MatchString(value) && referencePath(value)
}
