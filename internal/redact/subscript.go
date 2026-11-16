package redact

import "regexp"

// subscriptKey matches a subscript whose key names a credential, up to the
// assignment operator: app.config['SECRET_KEY'] =, headers["X-Api-Key"] =,
// os.environ['API_TOKEN'] =, $cfg['api_key'] =, m["apiKey"] =,
// config[:api_key] =, ENV['TOKEN'] ||=. The key words are those of the
// generic-api-key and password rules. Further subscripts on the same
// line may follow the key (cfg['api_key']['prod'] =). "==" and "===" are
// comparisons: the operator is then followed by "=", which no value accepts.
const subscriptKey = `(?i)\[[ \t]*[:"'` + "`" + `]?[A-Za-z0-9_.-]*` +
	`(?:access|auth|api|credential|creds|key|passw|passphrase|pwd|secret|token)` +
	`[A-Za-z0-9_.-]*["'` + "`" + `]?[ \t]*\]` +
	`(?:[ \t]*\[[^\]\r\n]*\])*[ \t]*(?:=|:=|\|\|=|\?\?=)[ \t]*`

// subscriptGate opens the subscript detectors: a credential key word right
// after a subscript's opening bracket.
var subscriptGate = regexp.MustCompile(`(?i)\[[ \t]*[:"'` + "`" + `]?[A-Za-z0-9_.-]*` +
	`(?:access|auth|api|credential|creds|key|passw|passphrase|pwd|secret|token)`)

// subscriptDetectors mask a value assigned through such a subscript. The
// vendored generic rule allows only quotes between the key and the
// operator, so the closing "]" hid these values (pentest P1). A quoted
// value (with an optional b, r or u prefix) is masked unless it only points
// at one (notPlaceholder). A bare value is masked when it has 10 or more
// characters and is not a plain word, so x['key'] = value and
// headers['Authorization'] = settings.AUTH_HEADER stay readable.
var subscriptDetectors = []patternDetector{
	{
		label: genericLabel,
		re: regexp.MustCompile(subscriptKey +
			"[bru]{0,2}(?:\"([^\"\\r\\n]*)\"|'([^'\\r\\n]*)'|`([^`\\r\\n]*)`)"),
		valid: notPlaceholder,
		when:  subscriptGate,
	},
	{
		label: genericLabel,
		re:    regexp.MustCompile(subscriptKey + `([A-Za-z0-9_.=+/-]{10,})[\s;,)}\]]`),
		valid: bareKeyValue,
		when:  subscriptGate,
	},
}

// bareKeyValue rejects placeholders and plain words (identifiers such as
// settings.API_KEY), as the gitleaks allowlist for generic values does.
func bareKeyValue(v string) bool {
	return notPlaceholder(v) && !wordValueRe.MatchString(v)
}
