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

// Protection (#62, pentest #67 finding 2, #250): the scanned repository's
// creep.yaml cannot turn the failing gate of a vulnerable app into a pass.
// A lowered budget, model timeout or output cap is accepted but starves
// nothing silently: the run ends incomplete (exit 4). Narrowing the
// scanners, raising a budget, picking the contract, tier or sandbox, or
// dropping the reports is a config error (exit 2). The operator's model and
// scanners come from the policy, so the project layer applies.
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
		{"model limits lowered but enough: gate fails", "model:\n  timeout_seconds: 60\n  max_output_bytes: 65536\n", exitcode.GateExceeded, "probable  sqli"},
		{"model timeout lowered to 1", "model:\n  timeout_seconds: 1\n", exitcode.Incomplete, "INCOMPLETE RUN (reason send_failed)"},
		{"model output cap lowered to 1024", "model:\n  max_output_bytes: 1024\n", exitcode.Incomplete, "INCOMPLETE RUN (reason send_failed)"},
		{"call budget raised", "budget:\n  max_calls: 501\n", exitcode.ConfigError, `key "budget.max_calls" cannot raise 500 to 501 in the project file`},
		{"scanners narrowed", "scanners:\n  enabled: []\n", exitcode.ConfigError, `key "scanners.enabled" cannot be set in the project file`},
		{"scanners restated", "scanners:\n  enabled: [gitleaks]\n", exitcode.ConfigError, `key "scanners.enabled" cannot be set in the project file`},
		{"model contract", "model:\n  contract: command\n", exitcode.ConfigError, `key "model.contract" cannot be set in the project file`},
		{"model tier", "model:\n  tier: small\n", exitcode.ConfigError, `key "model.tier" cannot be set in the project file`},
		{"sandbox enabled", "sandbox:\n  enabled: true\n", exitcode.ConfigError, `key "sandbox.enabled" cannot be set in the project file`},
		{"sandbox runtime", "sandbox:\n  runtime: podman\n", exitcode.ConfigError, `key "sandbox.runtime" cannot be set in the project file`},
		{"reports dropped", "report:\n  formats: []\n", exitcode.ConfigError, `key "report.formats" cannot be set in the project file`},
		{"output format", "output:\n  format: json\n", exitcode.ConfigError, `key "output.format" cannot be set in the project file`},
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
			code, out, errOut := runScanWith(limitDeps(m), "scan")
			checkScanResult(t, code, out, errOut, tt.wantCode, tt.want)
		})
	}
}

// Protection (#249): the operator's user-file gate is the floor for the
// project file. An SSRF finding (rated high) passes the built-in PR gate
// (probable:critical) but fails the operator's probable:high; a hostile
// creep.yaml that asks for the built-in gate back is a config error, and
// --config, which replaces the user and project files, ignores it.
func TestProjectFileCannotLoosenUserGate(t *testing.T) {
	const hostile = "gates:\n  pr: probable:critical\n"
	tests := []struct {
		name          string
		user, project string // "" means no file
		explicit      bool   // pass the user gate as --config instead
		wantCode      int
		want          string // in stdout for a scan that ran, in stderr otherwise
	}{
		{"built-in gate only: ssrf passes", "", "", false, exitcode.OK, "probable  ssrf"},
		{"user gate: ssrf fails", "gates:\n  pr: probable:high\n", "", false, exitcode.GateExceeded, "probable  ssrf"},
		{"hostile project restores built-in gate", "gates:\n  pr: probable:high\n", hostile, false, exitcode.ConfigError,
			`project "creep.yaml": gates.pr "probable:critical" is looser than the gate "probable:high" set by user "~/.creep/config.yaml"`},
		{"project disables gate", "gates:\n  pr: probable:high\n", "gates:\n  pr: none\n", false, exitcode.ConfigError, `gates.pr "none" is looser than the gate "probable:high"`},
		{"project equal to user gate", "gates:\n  pr: probable:high\n", "gates:\n  pr: probable:high\n", false, exitcode.GateExceeded, "probable  ssrf"},
		{"project stricter than user gate", "gates:\n  pr: probable:high\n", "gates:\n  pr: probable:low\n", false, exitcode.GateExceeded, "probable  ssrf"},
		{"--config ignores hostile project", "gates:\n  pr: probable:high\n", hostile, true, exitcode.GateExceeded, "probable  ssrf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"app.py": "@flask"}
			if tt.project != "" {
				files["creep.yaml"] = tt.project
			}
			scanRepo(t, files, "")
			setOperatorPolicy(t)
			args := []string{"scan"}
			switch {
			case tt.explicit:
				args = append(args, "--config", writeOutside(t, "ci.yaml", tt.user))
			case tt.user != "":
				writeUserConfig(t, tt.user)
			}
			m := &fakeModel{verdict: map[string]string{"ssrf": "vulnerable"}}
			code, out, errOut := runScanWith(limitDeps(m), args...)
			checkScanResult(t, code, out, errOut, tt.wantCode, tt.want)
		})
	}
}

func checkScanResult(t *testing.T, code int, out, errOut string, wantCode int, want string) {
	t.Helper()
	if code != wantCode {
		t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, wantCode, out, errOut)
	}
	got := out
	if code == exitcode.ConfigError {
		got = errOut
	}
	if !strings.Contains(got, want) {
		t.Errorf("output lacks %q\nstdout:\n%s\nstderr:\n%s", want, out, errOut)
	}
}

// setOperatorPolicy writes the operator's model and an enabled scanner to
// a policy outside the repository. PATH is empty, so the scanner is listed
// as missing, which never makes a run incomplete.
func setOperatorPolicy(t *testing.T) {
	t.Helper()
	data := "defaults:\n  model:\n    contract: openai\n    endpoint: https://models.example.invalid/v1\n    name: test-model\n  scanners:\n    enabled: [gitleaks]\n"
	t.Setenv(policyEnv, writeOutside(t, "org.yaml", data))
	t.Setenv("PATH", t.TempDir())
}

// writeUserConfig writes ~/.creep/config.yaml under a fresh home directory.
func writeUserConfig(t *testing.T, data string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	mustMkdir(t, filepath.Join(home, ".creep"))
	mustWrite(t, filepath.Join(home, filepath.FromSlash(userConfig)), data)
}

// writeOutside writes a config file outside the repository and returns its path.
func writeOutside(t *testing.T, name, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Fake model CLI needs, above the 1 s and 1 KiB minimums a project may set.
const (
	fakeCallSeconds = 10
	fakeOutputBytes = 4 << 10
)

// limitDeps refuses calls past the resolved budget.max_calls with the
// gateway's budget error, and fails a call whose model.timeout_seconds or
// model.max_output_bytes is below what the fake model needs with the error
// the gateway returns for a killed command (gateway/command_test.go), so the
// test shows each project value reaching the run and its effect.
func limitDeps(m *fakeModel) scanDeps {
	deps := fakeDeps(m, calibrate.TierM)
	deps.connect = func(r *config.Resolved, _ string, _ io.Writer) (modelLink, error) {
		cfg := r.Config
		send := func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
			switch {
			case m.calls >= cfg.Budget.MaxCalls:
				return nil, fmt.Errorf("send: %w", gateway.ErrBudgetExhausted)
			case cfg.Model.TimeoutSeconds < fakeCallSeconds:
				return nil, fmt.Errorf("exec: %w", gateway.ErrCommandTimeout)
			case cfg.Model.MaxOutputBytes < fakeOutputBytes:
				return nil, fmt.Errorf("exec: %w", gateway.ErrResponseTooLarge)
			}
			return m.send(ctx, c)
		}
		return modelLink{send: send, close: func() error { return nil }}, nil
	}
	return deps
}
