package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

// presetDoctor installs this test binary as a fake `program` on PATH, writes
// a config selecting preset, and consents to the resolved command through a
// policy. The fake behaves as mode (see fakeCLI).
func presetDoctor(t *testing.T, program, preset, mode string) string {
	t.Helper()
	cfgPath := scanRepo(t, map[string]string{"app.py": leakyApp}, "")
	bin := t.TempDir()
	installFake(t, filepath.Join(bin, program+exeSuffix()))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv(fakeCLIEnv, mode)
	t.Setenv(fakeStdinEnv, t.TempDir())
	cfg := fmt.Sprintf("model:\n  preset: %s\n  name: test-model\n  env: [%s, %s]\n", preset, fakeCLIEnv, fakeStdinEnv)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := config.Load(config.Inputs{Explicit: &config.File{Name: cfgPath, Data: []byte(cfg)}})
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := newModelCommand(r.Config.Model, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policy, []byte("consent: ['"+cmd.Endpoint()+"']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policyEnv, policy)
	return cfgPath
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// installFake copies the test binary to dst, so the gateway finds it on
// PATH under the preset's program name.
func installFake(t *testing.T, dst string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	// G302: the fake must be executable to be found on PATH; it lives in t.TempDir().
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, src); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// Acceptance (#7): every preset resolves to a command the gateway can run,
// a CLI that keeps its tools off passes the canary, and one that obeys the
// trap is caught with a fix naming the preset's flags.
func TestPresetsRunTheCanary(t *testing.T) {
	tests := []struct {
		program, preset, fix  string
		readsHost, unverified bool
	}{
		{"claude", "claude-code", `it already has --tools "" and --strict-mcp-config`, false, false},
		{"gemini", "gemini", "it already has --approval-mode default", true, false},
		{"codex", "codex", "it already has --sandbox read-only", true, true},
		{"ollama", "ollama", "ollama run has no tools", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.preset, func(t *testing.T) {
			cfg := presetDoctor(t, tt.program, tt.preset, "answer")
			code, stdout, stderr := runScanWith(commandDeps(), "--config", cfg, "doctor")
			if code != exitcode.OK || !strings.Contains(stdout, "tool canary passed") {
				t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
			}
			if warned := strings.Contains(stderr, "can read files outside its empty working directory"); warned != tt.readsHost {
				t.Errorf("host-read warning = %v, want %v: %s", warned, tt.readsHost, stderr)
			}
			if warned := strings.Contains(stderr, "is not verified against the real CLI"); warned != tt.unverified {
				t.Errorf("unverified warning = %v, want %v: %s", warned, tt.unverified, stderr)
			}
			if n := strings.Count(stderr, "warning: preset"); n > 1 {
				t.Errorf("%d warning lines, want at most one: %s", n, stderr)
			}
			t.Setenv(fakeCLIEnv, "obey")
			code, _, stderr = runScanWith(commandDeps(), "--config", cfg, "doctor")
			if code != exitcode.ModelOrSandbox || !strings.Contains(stderr, "has tools enabled") || !strings.Contains(stderr, tt.fix) {
				t.Fatalf("exit %d, stderr %s", code, stderr)
			}
		})
	}
}

// Protection (#7 F1): a preset whose CLI can read the host is announced at
// scan start, before the canary and before any repository text is sent.
func TestScanWarnsWhenPresetReadsHost(t *testing.T) {
	cfg := presetDoctor(t, "codex", "codex", "obey")
	code, _, stderr := runScanWith(commandDeps(), "--config", cfg, "scan")
	if code != exitcode.ModelOrSandbox {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	warn := strings.Index(stderr, `warning: preset "codex" is not verified`)
	if warn < 0 || warn > strings.Index(stderr, "tool canary") || !strings.Contains(stderr, "can read files") || !strings.Contains(stderr, "~/.ssh") {
		t.Errorf("stderr %s", stderr)
	}
}

// Protection (#7 A1): a preset under a policy lock on model.run is a config
// error (exit 2) before any program starts.
func TestPolicyLockStopsPreset(t *testing.T) {
	cfg := presetDoctor(t, "claude", "claude-code", "answer")
	policy := filepath.Join(t.TempDir(), "org.yaml")
	if err := os.WriteFile(policy, []byte("locked: [model.run]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policyEnv, policy)
	code, _, stderr := runScanWith(commandDeps(), "--config", cfg, "doctor")
	if code != exitcode.ConfigError || !strings.Contains(stderr, "which is locked by policy") {
		t.Errorf("exit %d, stderr %s", code, stderr)
	}
}

// Protection (#7, #62-style): a scanned repository's creep.yaml cannot pick
// a preset, even one that exists.
func TestProjectFileCannotSelectPreset(t *testing.T) {
	scanRepo(t, map[string]string{"app.py": leakyApp, "creep.yaml": "model:\n  preset: claude-code\n"}, "")
	code, _, stderr := runScanWith(commandDeps(), "doctor")
	if code != exitcode.ConfigError || !strings.Contains(stderr, "cannot be set in the project file") {
		t.Errorf("exit %d, stderr %s", code, stderr)
	}
}
