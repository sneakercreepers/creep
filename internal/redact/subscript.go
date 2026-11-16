package redact

import (
	"regexp"
	"strings"
)

// Key words of the password rule (any quoted value is masked) and of the
// generic-api-key rule (the value needs its shape).
const (
	anyValueWords    = `(?:passw|passphrase|pwd|secret)`
	shapedValueWords = `(?:access|auth|api|credential|creds|key|token)`
)

// subscriptKey matches a subscript whose key holds one of words, up to the
// assignment operator: app.config['SECRET_KEY'] =, headers["X-Api-Key"] =,
// os.environ['API_TOKEN'] =, $cfg['api_key'] =, m["apiKey"] =,
// config[:api_key] =, ENV['TOKEN'] ||=. Further subscripts on the same
// line may follow the key (cfg['api_key']['prod'] =). "==" and "===" are
// comparisons: the operator is then followed by "=", which no value accepts.
func subscriptKey(words string) string {
	return `(?i)\[[ \t]*[:"'` + "`" + `]?[A-Za-z0-9_.-]*` + words +
		`[A-Za-z0-9_.-]*["'` + "`" + `]?[ \t]*\]` +
		`(?:[ \t]*\[[^\]\r\n]*\])*[ \t]*(?:=|:=|\|\|=|\?\?=)[ \t]*`
}

// quotedValue is a quoted literal with an optional b, f, r or u prefix.
const quotedValue = "[bfru]{0,2}(?:\"([^\"\\r\\n]*)\"|'([^'\\r\\n]*)'|`([^`\\r\\n]*)`)"

// subscriptGate opens the subscript detectors: a credential key word right
// after a subscript's opening bracket.
var subscriptGate = regexp.MustCompile(`(?i)\[[ \t]*[:"'` + "`" + `]?[A-Za-z0-9_.-]*` +
	`(?:` + anyValueWords + `|` + shapedValueWords + `)`)

// subscriptDetectors mask a value assigned through such a subscript. The
// vendored generic rule allows only quotes between the key and the
// operator, so the closing "]" hid these values (pentest P1). They follow
// the rules they extend: under a password or secret key any quoted value is
// masked unless it only points at one (notPlaceholder), as the password rule
// does; under the generic words a quoted value needs the generic rule's
// shape (10 characters or more, not a plain word); a bare value is masked
// when it has that shape too. A key that only contains a word (author,
// keyboard_layout, api_version, token_type, public_key) is not a
// credential and is skipped (harmlessKey).
var subscriptDetectors = []patternDetector{
	{
		label: passwordLabel, re: regexp.MustCompile(subscriptKey(anyValueWords) + quotedValue),
		valid: notPlaceholder, when: subscriptGate, skip: harmlessKey,
	},
	{
		label: genericLabel, re: regexp.MustCompile(subscriptKey(shapedValueWords) + quotedValue),
		valid: genericShape, when: subscriptGate, skip: harmlessKey,
	},
	{
		label: genericLabel,
		re: regexp.MustCompile(subscriptKey(`(?:`+anyValueWords+`|`+shapedValueWords+`)`) +
			`([A-Za-z0-9_.=+/-]{10,})[\s;,)}\]]`),
		valid: genericShape, when: subscriptGate, skip: harmlessKey,
	},
}

// genericShape is the generic-api-key value shape: 10 characters or more
// and not a plain word (letters, "_", "." and "-" only, the gitleaks
// allowlist), and not a reference to a value.
func genericShape(v string) bool {
	return len(v) >= 10 && notPlaceholder(v) && !wordValueRe.MatchString(v)
}

// harmlessWordRe matches key names that contain a credential word without
// naming a credential, after the gitleaks generic-api-key allowlist.
var harmlessWordRe = regexp.MustCompile(`(?i)(?:^|[_.-])authors?(?:[_.-]?(?:name|email|id|url))?$|keyboard|monkey|donkey|turkey|keystroke|keyword|keyframe|keypress|keycode|keying|tokeni[sz]|accessib|accessor|csrf[_.-]?token|` +
	`(?:api|auth|token|access|key|credentials?|creds)[_.-]?(?:version|url|uri|endpoint|base|host|path|name|id|type|method|mode|provider|scheme|file|alias|length|size|count|level|prefix|field|ttl|expiry|expires|timeout|enabled)s?$|` +
	`^(?:public|pub|primary|foreign|sort|partition|row|cache|hot|idx|index|natural|schema|sequence|bucket|lookup|hash|unique|composite)[_.-]?key$`)

var credentialWordRe = regexp.MustCompile(`(?i)` + anyValueWords + `|` + shapedValueWords)

// harmlessKey reports a match whose subscripts, the text before the value,
// name no credential: every key holding a credential word only looks like
// one. Any credential key among nested subscripts (x['api_url']['token'])
// keeps the match.
func harmlessKey(prefix string) bool {
	for _, part := range strings.Split(prefix, "[")[1:] {
		key, _, _ := strings.Cut(part, "]")
		key = strings.Trim(key, " \t:\"'`")
		if credentialWordRe.MatchString(key) && !harmlessWordRe.MatchString(key) {
			return false
		}
	}
	return true
}
