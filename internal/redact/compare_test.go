package redact

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// A comparison against a word is code, not a key (#167); an assignment, or
// a compared value that is not a plain word, is still masked.
func TestGenericKeyComparedWord(t *testing.T) {
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
		{"assigned hex", `const key = "a8f5f167f44f4964e6c998dee827110c";`, true},
		{"yaml key", `key: "Zx9kQ2mP7vL4rT8wQ"`, true},
		{"compared hex", `if (key === "a8f5f167f44f4964e6c998dee827110c") {}`, true},
		{"compared with digit", `if (apiKey == 'hunter2hunter2') {}`, true},
		{"compared base64", `if token == "c2VjcmV0K3Rva2VuL3ZhbHVl"`, true},
		{"assign then compare", "key = \"a8f5f167f44f4964e6c9\"\nif (key === \"constructor\") {}", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := mustRedact(t, newRedactor(t), tc.text)
			if got := strings.Contains(out, "<SECRET_"); got != tc.masked {
				t.Fatalf("masked = %v, want %v: %q", got, tc.masked, out)
			}
			if !tc.masked && out != tc.text {
				t.Fatalf("changed %q to %q", tc.text, out)
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
