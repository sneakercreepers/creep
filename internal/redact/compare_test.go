package redact

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// A comparison against a word is code, not a key (#167); an assignment, or
// a compared value that is not a plain word, is still masked.
func TestGenericKeyComparedWord(t *testing.T) {
	// Values are generated so the repository's own secret scan stays clean.
	rng := rand.New(rand.NewPCG(63, 64))
	values := strings.NewReplacer("HEX", fakeToken(rng, "0123456789abcdef", 32), "B64", fakeToken(rng, base64Chars, 24))
	tests := []struct {
		name   string
		text   string
		masked bool
	}{
		{"js strict compare", `if (key === "constructor") continue;`, false},
		{"loose compare", `if key == "constructor":`, false},
		{"single quotes", `if (key === 'constructor') {}`, false},
		{"dotted word", `if (apiKey == "content.type.header") {}`, false},
		{"safe twin line", `    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;`, false},
		{"assigned word", `key = "constructorvalue"`, true},
		{"assigned hex", `const key = "HEX";`, true},
		{"yaml key", `key: "B64"`, true},
		{"compared hex", `if (key === "HEX") {}`, true},
		{"compared with digit", `if (apiKey == 'hunter2hunter2') {}`, true},
		{"compared base64", `if token == "B64"`, true},
		{"assign then compare", "key = \"HEX\"\nif (key === \"constructor\") {}", true},
		// Item 3 of #190, by design: a plain word compared is not a key.
		{"password compared word", `if password == "CorrectHorseBatteryStaple":`, false},
		// Item 4 of #190: "!=", "!==" and subscripts the vendored rule misses.
		{"strict not equal", `if (secret !== "B64") {}`, true},
		{"not equal", `if token != "HEX" {`, true},
		{"not equal, no blanks", `if(apiKey!=='HEX'){}`, true},
		{"subscript compare", `if os.environ["API_KEY"] == "B64":`, true},
		{"subscript strict compare", `if (process.env['TOKEN'] === 'HEX') {}`, true},
		{"subscript not equal", `if ENV['SECRET'] != "B64"`, true},
		{"subscript password short", `if ENV["PASSWORD"] != "x9"`, true},
		{"not equal word", `if (typeof secret !== "undefined") {}`, false},
		{"subscript compare word", `if os.environ["API_KEY"] == "production":`, false},
		// A password word compared is masked at any length, as assigned
		// (reviewer on #293); a plain word under it stays readable.
		{"not equal short", `if secret != "abc123" {`, true},
		{"password compare short", `if password == "hunter2!" {`, true},
		{"password strict compare short", `if (pwd === 'x9') {}`, true},
		{"password compare word", `if (password !== 'undefined') {}`, false},
		{"password compare placeholder", `if password != "${PASSWORD}" {`, false},
		{"shaped word short", `if token != "abc123" {`, false},
		// Further operators and lookups the vendored rule misses.
		{"shell test quoted key", `[ "$API_TOKEN" != "HEX" ]`, true},
		{"shell test braces", `[ "${API_TOKEN}" != "HEX" ]`, true},
		{"java equals", `if (token.equals("B64")) {`, true},
		{"java equals ignore case", `if (apiKey.equalsIgnoreCase("HEX")) {`, true},
		{"java equals password", `if (password.equals("hunter2!")) {`, true},
		{"java equals harmless key", `if (tokenType.equals("Bearer-2024-v1")) {`, false},
		{"sql not equal value", `q := "SELECT id FROM users WHERE api_key <> 'HEX'"`, true},
		{"unicode not equal", `if token ≠ "B64"`, true},
		{"unicode not equal password", `if secret ≠ "x9"`, true},
		{"getenv compare", `if os.getenv("API_KEY") != "B64":`, true},
		{"get compare", `if cfg.get('token') == "HEX":`, true},
		{"getenv compare word", `if os.getenv("API_KEY") == "production":`, false},
		{"get harmless key", `if cfg.get("api_version") == "2024-01-01":`, false},
		{"call without key", `if strings.ToLower(token) != "bearer":`, false},
		{"not equal reference", `if token != "${TOKEN}" {`, false},
		{"not equal harmless key", `if key_type != "rsa-sha2-512" {`, false},
		{"subscript harmless key", `if cfg["api_version"] == "2024-01-01":`, false},
		{"not equal nil", `if err != nil && token != nil {`, false},
		{"not equal prose", `msg := "the token != the key" + "\n"`, false},
		{"sql not equal", `q := "SELECT id FROM users WHERE api_key != '' AND id = $1"`, false},
		{"hex digest compare", `if sum != "HEX" {`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			text := values.Replace(tc.text)
			out := mustRedact(t, newRedactor(t), text)
			if got := strings.Contains(out, "<SECRET_"); got != tc.masked {
				t.Fatalf("masked = %v, want %v: %q", got, tc.masked, out)
			}
			if !tc.masked && out != text {
				t.Fatalf("changed %q to %q", text, out)
			}
		})
	}
}

// The exemption must not leave any part of an assigned secret visible.
func TestGenericKeyAssignedStillHidden(t *testing.T) {
	secret := fakeToken(rand.New(rand.NewPCG(61, 62)), alnum, 20)
	for _, text := range []string{
		`key = "` + secret + `"`,
		`key := "` + secret + `"`,
		`"key": "` + secret + `",`,
		`key=` + secret,
		`if (key === "constructor") { key = "` + secret + `"; }`,
	} {
		if out := mustRedact(t, newRedactor(t), text); strings.Contains(out, secret[:8]) {
			t.Errorf("%q leaked: %q", text, out)
		}
	}
}
