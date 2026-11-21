package cli

import (
	"testing"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

// A bad policy consent entry fails when the configuration loads, for every
// command, with exit 2 and the entry escaped, not at the first model call
// (#116). Valid entries, command endpoints included, still load.
func TestBadPolicyConsentFailsAtLoad(t *testing.T) {
	tests := []struct {
		name, entry string
		ok          bool
	}{
		{"path", "https://api.example.com/v1", false},
		{"userinfo", "https://user@api.example.com", false},
		{"query", "https://api.example.com?x=1", false},
		{"scheme", "ftp://api.example.com", false},
		{"numeric host", "https://0x7f000001", false},
		{"control runes", "https://api.example.com/\x1b[31m", false},
		{"origin", "https://api.example.com", true},
		{"origin with port", "https://10.0.0.5:8443/", true},
		{"command endpoint", "command://claude-0123456789abcdef", true},
	}
	for _, cmd := range [][]string{{"config", "explain"}, {"doctor"}, {"scan"}} {
		for _, tt := range tests {
			t.Run(cmd[0]+"/"+tt.name, func(t *testing.T) {
				configEnv(t, "consent:\n  - \""+yamlEscape(tt.entry)+"\"\n", "", "")
				code, _, stderr := run(cmd...)
				if tt.ok {
					if cmd[0] == "config" && code != exitcode.OK {
						t.Fatalf("exit code = %d, want 0\nstderr: %s", code, stderr)
					}
					return
				}
				if code != exitcode.ConfigError {
					t.Fatalf("exit code = %d, want %d\nstderr: %s", code, exitcode.ConfigError, stderr)
				}
				assertContains(t, "stderr", stderr, []string{"CREEP_POLICY", "policy consent entry"})
				assertNoControl(t, stderr)
			})
		}
	}
}

// yamlEscape writes the ESC rune as a YAML double-quoted escape.
func yamlEscape(s string) string {
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		if s[i] == 0x1b {
			out = append(out, `\e`...)
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}
