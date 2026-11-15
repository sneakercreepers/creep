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
