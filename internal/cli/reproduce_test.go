package cli

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/sandbox"
)

// sandboxOnly is a user config of body only: no model at all.
func sandboxOnly(t *testing.T, body string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "creep.yaml")
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// noModel is the deps of a command that must never reach a model: a
// connect or calibration call fails the test.
func noModel(t *testing.T) scanDeps {
	t.Helper()
	deps := noModelDeps
	deps.connect = func(*config.Resolved, string, io.Writer) (modelLink, error) {
		t.Error("creep reproduce opened a model link")
		return modelLink{}, errors.New("no model")
	}
	return deps
}

// scannedBundle runs a scan whose PoC verifies the Flask app's first SQL
// injection in every run, so .creep/bundles holds its bundle.
func scannedBundle(t *testing.T) string {
	t.Helper()
	code, out, _, _ := pocScan(t, sqlDelayPoC, delayApp(repeatBool(true, 10), "[]"))
	if code != exitcode.GateExceeded {
		t.Fatalf("scan exit %d\n%s", code, out)
	}
	return sqliFinding(t).ID
}

// Protection (#25, acceptance): creep reproduce reruns a bundle's PoC
// with no model configured and no model link: the config has no model
// section, every model hook fails the test, and the PoC still runs its
// runs against a fresh build, offline in the sandbox.
func TestReproduceNeedsNoModel(t *testing.T) {
	tests := []struct {
		name string
		slow []bool
		code int
		want string
	}{
		{"reproduced", repeatBool(true, 5), exitcode.OK, "reproduced: verified in 5/5 runs (the scan: 5/5)"},
		{"intermittent", []bool{false, true, false, false, false}, exitcode.OK, "reproduced: verified in 1/5 runs, intermittent"},
		{"not reproduced", nil, exitcode.GateExceeded, "not reproduced: verified in 0/5 runs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := scannedBundle(t)
			fb := &fakeBuilder{app: builtApp, port: 5000, exchange: delayApp(tt.slow, "[]")}
			opened := 0
			deps := withBuilder(noModel(t), fb, nil, &opened)
			code, stdout, stderr := runScanWith(deps, "--config", sandboxOnly(t, sandboxOn), "reproduce", id)
			if code != tt.code || !strings.Contains(stdout, tt.want) {
				t.Fatalf("exit %d, want %d and %q\nstdout %s\nstderr %s", code, tt.code, tt.want, stdout, stderr)
			}
			if opened != 1 || fb.builds != 1 || fb.started != 1 || fb.closes != 1 || fb.exchanges != 5 {
				t.Errorf("opened %d, builds %d, starts %d, closes %d, exchanges %d", opened, fb.builds, fb.started, fb.closes, fb.exchanges)
			}
			if !strings.Contains(stdout, "reproduce "+id+": sqli with sql_payload, 5 runs") {
				t.Errorf("stdout %s", stdout)
			}
		})
	}
}

// TestReproduceFailsClosed: every way reproduce cannot run exits non-zero
// before or without running a PoC: usage, the sandbox off, a missing,
// unsafe or tampered bundle (2), no runtime or no app (3).
func TestReproduceFailsClosed(t *testing.T) {
	tamper := func(field string, value any) func(t *testing.T, id string) {
		return func(t *testing.T, id string) { editBundle(t, id, field, value) }
	}
	tests := []struct {
		name   string
		args   []string
		cfg    string
		prep   func(t *testing.T, id string)
		fb     fakeBuilder
		checks []sandbox.Status
		code   int
		want   string
	}{
		{"no ID", []string{"reproduce"}, "", nil, fakeBuilder{}, nil, exitcode.ConfigError, "want exactly one finding ID"},
		{"two IDs", []string{"reproduce", "a", "b"}, "", nil, fakeBuilder{}, nil, exitcode.ConfigError, "want exactly one finding ID"},
		{"unsafe ID", []string{"reproduce", "../report"}, "", nil, fakeBuilder{}, nil, exitcode.ConfigError, "invalid finding ID"},
		{"colon ID", []string{"reproduce", "sink-1:x"}, "", nil, fakeBuilder{}, nil, exitcode.ConfigError, "invalid finding ID"},
		{"no bundle", []string{"reproduce", "sink-99"}, "", nil, fakeBuilder{}, nil, exitcode.ConfigError, "no reproduction bundle for sink-99"},
		{"sandbox off", nil, "off", nil, fakeBuilder{}, nil, exitcode.ConfigError, "needs sandbox.enabled"},
		{"rate tampered", nil, "", tamper("rate", map[string]int{"verified": 4, "runs": 5}), fakeBuilder{}, nil, exitcode.ConfigError, "rate"},
		{"other finding", nil, "", tamper("finding", "sink-2"), fakeBuilder{}, nil, exitcode.ConfigError, "another finding"},
		{"class of another template", nil, "", tamper("class", "path_traversal"), fakeBuilder{}, nil, exitcode.ConfigError, "does not prove"},
		{"PoC refused", nil, "", tamper("poc", map[string]any{"template": "shell"}), fakeBuilder{}, nil, exitcode.ConfigError, "poc refused"},
		{"no runtime", nil, "", nil, fakeBuilder{}, []sandbox.Status{missingDocker, missingPodman}, exitcode.ModelOrSandbox, "no usable docker or podman"},
		{"no build", nil, "", nil, fakeBuilder{app: sandbox.App{Unavailable: sandbox.BuildNoFile}}, nil, exitcode.ModelOrSandbox, "no_build_file"},
		{"no port", nil, "", nil, fakeBuilder{app: builtApp}, nil, exitcode.ModelOrSandbox, "no_port"},
		{"runner fails", nil, "", nil, fakeBuilder{app: builtApp, port: 5000}, nil, exitcode.ModelOrSandbox, "no exchange"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := scannedBundle(t)
			if tt.prep != nil {
				tt.prep(t, id)
			}
			args := tt.args
			if args == nil {
				args = []string{"reproduce", id}
			}
			cfg := sandboxOnly(t, sandboxOn)
			if tt.cfg == "off" {
				cfg = sandboxOnly(t, "sandbox:\n  enabled: false\n")
			}
			opened := 0
			deps := withBuilder(noModel(t), &tt.fb, nil, &opened)
			if tt.checks != nil {
				deps.sandbox.detect = withSandbox(deps, tt.checks, nil, nil).sandbox.detect
			}
			code, stdout, stderr := runScanWith(deps, append([]string{"--config", cfg}, args...)...)
			if code != tt.code || !strings.Contains(stdout+stderr, tt.want) {
				t.Fatalf("exit %d, want %d and %q\nstdout %s\nstderr %s", code, tt.code, tt.want, stdout, stderr)
			}
			if tt.fb.exchanges > 1 || tt.fb.closes != tt.fb.builds {
				t.Errorf("%d exchanges, %d builds, %d closes", tt.fb.exchanges, tt.fb.builds, tt.fb.closes)
			}
		})
	}
}

// editBundle rewrites one field of a finding's bundle in .creep/bundles.
func editBundle(t *testing.T, id, field string, value any) {
	t.Helper()
	name := filepath.Join(stateDir, bundleName(id))
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m[field] = value
	if data, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestScanRemovesStaleBundles: a bundle the repository committed under
// .creep, or one an earlier scan left, is gone once a scan opens its
// state, so reproduce never runs one this run did not write.
func TestScanRemovesStaleBundles(t *testing.T) {
	files := map[string]string{"app.py": "@flask", ".creep/bundles/sink-7.json": `{"version":1}`}
	cfg := scanRepo(t, files, "")
	if code, _, stderr := runScanWith(fakeDeps(&fakeModel{verdict: sqliVulnerable}, "M"), "--config", cfg, "scan"); code != exitcode.GateExceeded {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(stateDir, bundleDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale bundles kept: %v", err)
	}
}
