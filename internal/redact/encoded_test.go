package redact

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

const lowerAlnum = "abcdefghijklmnopqrstuvwxyz0123456789"

// webhookURL is a URL-shaped secret and the parts of it that must not leak.
type webhookURL struct {
	url    string
	hidden []string
}

// Hosts are split so this file holds no literal webhook pattern.
func fakeDiscordURL(rng *rand.Rand) webhookURL {
	id, token := fakeToken(rng, digits, 19), fakeToken(rng, tokenChars, 68)
	return webhookURL{"https://discord" + ".com/api/webhooks/" + id + "/" + token, []string{id, token}}
}

func fakeSlackURL(rng *rand.Rand) webhookURL {
	team, bot, token := "T"+fakeToken(rng, alnum, 10), "B"+fakeToken(rng, alnum, 10), fakeToken(rng, alnum, 24)
	return webhookURL{"https://hooks.slack" + ".com/services/" + team + "/" + bot + "/" + token, []string{team, bot, token}}
}

func fakeUUID(rng *rand.Rand) string {
	return fakeToken(rng, lowerAlnum, 8) + "-" + fakeToken(rng, lowerAlnum, 4) + "-" +
		fakeToken(rng, lowerAlnum, 4) + "-" + fakeToken(rng, lowerAlnum, 4) + "-" + fakeToken(rng, lowerAlnum, 12)
}

func fakeTeamsURL(rng *rand.Rand) webhookURL {
	group, tenant, hook, owner := fakeUUID(rng), fakeUUID(rng), fakeToken(rng, lowerAlnum, 32), fakeUUID(rng)
	url := "https://acme.webhook.office" + ".com/webhookb2/" + group + "@" + tenant + "/IncomingWebhook/" + hook + "/" + owner
	return webhookURL{url, []string{group, tenant, hook, owner}}
}

// Encodings of the separators, as serializers and query strings write them.
var separatorEncodings = []struct {
	name     string
	encoding func(string) string
}{
	{"json escaped", func(u string) string { return strings.ReplaceAll(u, "/", `\/`) }},
	{"percent upper", strings.NewReplacer("/", "%2F", ":", "%3A").Replace},
	{"percent lower", strings.NewReplacer("/", "%2f", ":", "%3a").Replace},
	{"percent mixed", strings.NewReplacer("/", "%2f", ":", "%3A").Replace},
	{"plain", func(u string) string { return u }},
}

// Acceptance (#151): webhook URLs with escaped or percent-encoded separators
// lose every byte of their id and token, through Redact and File.
func TestRedactEncodedWebhooks(t *testing.T) {
	rng := rand.New(rand.NewPCG(151, 1))
	makers := map[string]func(*rand.Rand) webhookURL{
		"discord": fakeDiscordURL, "slack": fakeSlackURL, "teams": fakeTeamsURL,
	}
	contexts := []struct{ before, after string }{
		{`{"webhook":"`, `"}` + "\n"},
		{"GET /notify?target=", "&retry=1 HTTP/1.1\n"},
		{"", ""},
	}
	for name, mk := range makers {
		for _, enc := range separatorEncodings {
			for _, c := range contexts {
				hook := mk(rng)
				text := c.before + enc.encoding(hook.url) + c.after
				assertHidden(t, name+"/"+enc.name, text, enc.encoding(hook.url), encodeAll(enc.encoding, hook.hidden))
			}
		}
	}
}

func encodeAll(encoding func(string) string, parts []string) []string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = encoding(p)
	}
	return out
}

// assertHidden checks that no 8-byte window of any hidden part reaches the
// output of Redact or File, nor of a later fragment that reuses the secret.
func assertHidden(t *testing.T, name, text, reuse string, hidden []string) {
	t.Helper()
	r := newRedactor(t)
	viaRedact := mustRedact(t, r, text)
	viaFile, err := newRedactor(t).File([]byte(text))
	if err != nil {
		t.Fatalf("%s: File: %v", name, err)
	}
	again := mustRedact(t, r, "x := "+reuse+"\n")
	for _, out := range []string{viaRedact, viaFile, again} {
		if w := leakedWindow(windows(hidden), out); w != "" {
			t.Fatalf("%s: %q leaked\ninput  %q\noutput %q", name, w, text, out)
		}
	}
}

// Escaped or encoded URLs that hold no secret stay as they are, as do
// near-misses of the webhook shapes.
func TestEncodedURLsWithoutSecretUnchanged(t *testing.T) {
	tests := []string{
		`{"url":"https:\/\/example.com\/a\/b"}`,
		`"homepage": "https:\/\/discord.com\/developers\/docs\/resources\/webhook"`,
		"next=https%3A%2F%2Fexample.com%2Flogin%3Fx%3D1",
		`see https:\/\/discord.com\/api\/webhooks\/{id}\/{token}`,
		"https%3a%2f%2fhooks.slack" + ".com%2fservices%2fshort",
		`path := "a\/b" + "%2Fc" + "%3"`,
		`%2`, `\`, `%`, `%2G%3B\x`,
	}
	for _, text := range tests {
		if out := mustRedact(t, newRedactor(t), text); out != text {
			t.Errorf("Redact(%q) = %q, want it unchanged", text, out)
		}
	}
}

// Every decoded byte maps back to the bytes that encode it, so a span over
// decoded text covers its escapes whole.
func TestDecodeSeparators(t *testing.T) {
	tests := []struct {
		in, decoded string
		starts      []int
	}{
		{"", "", []int{0}},
		{"ab", "ab", []int{0, 1, 2}},
		{`a\/b`, "a/b", []int{0, 1, 3, 4}},
		{"%2f%3A", "/:", []int{0, 3, 6}},
		{`\\/`, `\/`, []int{0, 1, 3}},
		{"%2", "%2", []int{0, 1, 2}},
		{`x\`, `x\`, []int{0, 1, 2}},
		{"%%2F", "%/", []int{0, 1, 4}},
	}
	for _, tt := range tests {
		got, starts := decodeSeparators(tt.in)
		if got != tt.decoded || !slices.Equal(starts, tt.starts) {
			t.Errorf("decodeSeparators(%q) = %q, %v; want %q, %v", tt.in, got, starts, tt.decoded, tt.starts)
		}
		if decodedOnly(tt.in) != tt.decoded {
			t.Errorf("decodedOnly(%q) = %q, want %q", tt.in, decodedOnly(tt.in), tt.decoded)
		}
	}
}

// The webhook rules are among the URL-shaped rules that run on decoded text;
// a rule that only has "/" inside a character class (base64) is not.
func TestURLShapedRules(t *testing.T) {
	rules, err := defaultRules()
	if err != nil {
		t.Fatal(err)
	}
	shaped := map[string]bool{}
	for _, r := range rules {
		shaped[r.label] = r.urlShaped
	}
	for _, label := range []string{"SECRET_DISCORD_WEBHOOK_TOKEN", "SECRET_SLACK_WEBHOOK_URL", "SECRET_MICROSOFT_TEAMS_WEBHOOK"} {
		if !shaped[label] {
			t.Errorf("%s is not URL-shaped", label)
		}
	}
	if shaped["SECRET_PRIVATE_KEY"] || shaped["SECRET_GENERIC_API_KEY"] {
		t.Error("a rule without a literal \"/\" is URL-shaped")
	}
}
