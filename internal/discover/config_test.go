package discover

import (
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/redact"
)

// JSON is config (#366 tester): a policy, app settings or rules a program
// loads are security-relevant, so a JSON file is read and sent like code.
// One that fits no discovery call or redaction is data and listed
// not_code by design; a lockfile is never opened; a NUL in UTF-8 JSON
// still fails closed.
func TestReadsJSONConfig(t *testing.T) {
	policy := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}` + "\n"
	tests := []struct {
		name   string
		path   string
		src    string
		cov    Coverage
		reason Reason
		calls  int
	}{
		{"policy", "iam/policy.json", policy, CoverageReadFull, ReasonNone, 1},
		{"manifest", "package.json", `{"scripts":{"x":"exec(rm)"}}`, CoverageReadFull, ReasonNone, 1},
		{"over one tier S call", "fixtures/users.json", strings.Repeat(`{"id":1},`+"\n", 2000), CoverageNotSource, ReasonNotCode, 0},
		{"over redact.MaxFileBytes", "fixtures/big.json", strings.Repeat(`{"id":1},`+"\n", redact.MaxFileBytes/10+1), CoverageNotSource, ReasonNotCode, 0},
		{"one long line", "dist/data.json", `{"k":"` + strings.Repeat("x", redact.MaxLineBytes+1) + `"}` + "\n", CoverageNotSource, ReasonNotCode, 0},
		{"lockfile", "web/package-lock.json", "{}\n", CoverageNotSource, ReasonNotCode, 0},
		{"NUL in UTF-8 JSON", "config/app.json", "{\"a\":\"\x00\"}\n", CoverageNotRead, ReasonReadFailed, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var prompts []string
			res, err := runPaths(t, TierS, []string{tt.path}, map[string]string{tt.path: tt.src}, honestReply, &prompts)
			if err != nil {
				t.Fatal(err)
			}
			if f := fileOf(t, res, 0); f.Coverage != tt.cov || f.Reason != tt.reason {
				t.Errorf("file = %+v, want coverage %d reason %q", f, tt.cov, tt.reason)
			}
			if len(prompts) != tt.calls {
				t.Errorf("%d calls, want %d", len(prompts), tt.calls)
			}
		})
	}
}
