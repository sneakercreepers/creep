package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
)

// Protection (#62, pentest #67 finding 2): the scanned repository's
// creep.yaml cannot turn the failing gate of a vulnerable app into a pass.
// A lowered budget is accepted but starves nothing silently: the run ends
// incomplete (exit 4). Narrowing the scanners, raising a budget, or picking
// the contract or the sandbox is a config error (exit 2). The operator's
// model and scanners come from the policy, so the project layer applies.
func TestProjectFileCannotStarveScanIntoPass(t *testing.T) {
	tests := []struct {
		name     string
		project  string // "" means no ./creep.yaml
		wantCode int
		want     string // in stdout for a scan that ran, in stderr otherwise
	}{
		{"no project file: gate fails", "", exitcode.GateExceeded, "probable  sqli"},
		{"budget lowered but enough: gate fails", "budget:\n  max_calls: 100\n  max_tokens: 1000000\n", exitcode.GateExceeded, "probable  sqli"},
		{"token budget lowered to 1", "budget:\n  max_tokens: 1\n", exitcode.Incomplete, "INCOMPLETE RUN (reason budget)"},
		{"call budget lowered to 1", "budget:\n  max_calls: 1\n", exitcode.Incomplete, "INCOMPLETE RUN (reason budget)"},
		{"call budget raised", "budget:\n  max_calls: 501\n", exitcode.ConfigError, `key "budget.max_calls" cannot raise 500 to 501 in the project file`},
		{"scanners narrowed", "scanners:\n  enabled: []\n", exitcode.ConfigError, `key "scanners.enabled" cannot be set in the project file`},
		{"scanners restated", "scanners:\n  enabled: [gitleaks]\n", exitcode.ConfigError, `key "scanners.enabled" cannot be set in the project file`},
		{"model contract", "model:\n  contract: command\n", exitcode.ConfigError, `key "model.contract" cannot be set in the project file`},
		{"sandbox enabled", "sandbox:\n  enabled: true\n", exitcode.ConfigError, `key "sandbox.enabled" cannot be set in the project file`},
		{"sandbox runtime", "sandbox:\n  runtime: podman\n", exitcode.ConfigError, `key "sandbox.runtime" cannot be set in the project file`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"app.py": "@flask"}
			if tt.project != "" {
				files["creep.yaml"] = tt.project
			}
			scanRepo(t, files, "")
			setOperatorPolicy(t)
			m := &fakeModel{verdict: map[string]string{"sql_injection": "vulnerable"}}
			code, out, errOut := runScanWith(callBudgetDeps(m), "scan")
			if code != tt.wantCode {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out, errOut)
			}
			got := out
			if code == exitcode.ConfigError {
				got = errOut
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("output lacks %q\nstdout:\n%s\nstderr:\n%s", tt.want, out, errOut)
			}
		})
	}
}

// setOperatorPolicy writes the operator's model and an enabled scanner to
// a policy outside the repository. PATH is empty, so the scanner is listed
// as missing, which never makes a run incomplete.
func setOperatorPolicy(t *testing.T) {
	t.Helper()
	policy := filepath.Join(t.TempDir(), "org.yaml")
	data := "defaults:\n  model:\n    contract: openai\n    endpoint: https://models.example.invalid/v1\n    name: test-model\n  scanners:\n    enabled: [gitleaks]\n"
	if err := os.WriteFile(policy, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policyEnv, policy)
	t.Setenv("PATH", t.TempDir())
}

// callBudgetDeps refuses calls past the resolved budget.max_calls with the
// gateway's budget error, as the real link does (gateway/budget_test.go),
// so the test shows the project value reaching the run and its effect.
func callBudgetDeps(m *fakeModel) scanDeps {
	deps := fakeDeps(m, calibrate.TierM)
	deps.connect = func(r *config.Resolved, _ string, _ io.Writer) (modelLink, error) {
		limit := r.Config.Budget.MaxCalls
		send := func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
			if m.calls >= limit {
				return nil, fmt.Errorf("send: %w", gateway.ErrBudgetExhausted)
			}
			return m.send(ctx, c)
		}
		return modelLink{send: send, close: func() error { return nil }}, nil
	}
	return deps
}
