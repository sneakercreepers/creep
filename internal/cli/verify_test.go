package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/sandbox"
)

const sandboxOn = "sandbox:\n  enabled: true\n"

// fakeBuilder stands in for a *sandbox.Sandbox: it records the build and
// every Close, and answers as told.
type fakeBuilder struct {
	app      sandbox.App
	err      error
	closeErr error
	wait     bool // block until the build's context ends, as a hung build would
	probe    func(sandbox.Repo)
	repo     sandbox.Repo
	builds   int
	closes   int
}

func (f *fakeBuilder) Build(ctx context.Context, repo sandbox.Repo) (sandbox.App, error) {
	f.builds++
	f.repo = repo
	if f.probe != nil {
		f.probe(repo)
	}
	if f.wait {
		<-ctx.Done()
		return sandbox.App{}, fmt.Errorf("sandbox build: %w", ctx.Err())
	}
	return f.app, f.err
}

func (f *fakeBuilder) Close() error {
	f.closes++
	return f.closeErr
}

// withBuilder gives deps a usable rootless Docker whose sandbox is fb, or
// fails to open with openErr; opened counts the opens.
func withBuilder(deps scanDeps, fb *fakeBuilder, openErr error, opened *int) scanDeps {
	deps = withSandbox(deps, []sandbox.Status{rootlessDocker}, nil, nil)
	deps.sandbox.open = func(st sandbox.Status, runID string) (appBuilder, error) {
		*opened++
		if st.Runtime != sandbox.Docker || runID == "" {
			return nil, errors.New("wrong runtime or run")
		}
		if openErr != nil {
			return nil, openErr
		}
		return fb, nil
	}
	return deps
}

// Protection (#23, threat model X13-X15): whatever the build does, the
// scan exits as it does with the sandbox off, writes its reports with the
// reason, keeps every finding probable, prints nothing unescaped, and
// closes a sandbox it opened exactly once.
func TestBuildFailureNeverFailsScan(t *testing.T) {
	hostile := errors.New("denied \x1b[2J")
	tests := []struct {
		name    string
		fb      fakeBuilder
		openErr error
		want    string // in report.md
	}{
		{"no build file", fakeBuilder{app: sandbox.App{Unavailable: sandbox.BuildNoFile}}, nil, "no_build_file"},
		{"refused dockerfile", fakeBuilder{app: sandbox.App{Unavailable: sandbox.BuildDockerfileRefused, Detail: "add_url"}}, nil, "dockerfile_refused: add_url"},
		{"failed build", fakeBuilder{app: sandbox.App{Unavailable: sandbox.BuildFailed, Detail: "exit_1"}}, nil, "build_failed: exit_1"},
		{"detail not an ID", fakeBuilder{app: sandbox.App{Unavailable: sandbox.BuildFailed, Detail: "x \x1b"}}, nil, "(`build_failed`)"},
		{"build error", fakeBuilder{err: hostile}, nil, "sandbox_error: build"},
		{"interrupted", fakeBuilder{err: sandbox.ErrInterrupted}, nil, "`interrupted`"},
		{"cleanup fails", fakeBuilder{app: sandbox.App{Unavailable: sandbox.BuildNoFile}, closeErr: hostile}, nil, "no_build_file"},
		{"open fails", fakeBuilder{}, hostile, "sandbox_error: open"},
		{"built", fakeBuilder{app: sandbox.App{Image: "sha256:" + strings.Repeat("a", 64)}}, nil, "built offline"},
	}
	flask := map[string]string{"app.py": testApp(t, "flask")}
	base, _, _ := runScanWith(fakeDeps(&fakeModel{verdict: sqliVulnerable}, calibrate.TierM), "--config", scanRepo(t, flask, ""), "scan")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opened := 0
			deps := withBuilder(fakeDeps(&fakeModel{verdict: sqliVulnerable}, calibrate.TierM), &tt.fb, tt.openErr, &opened)
			cfg := scanRepo(t, flask, sandboxOn)
			code, stdout, stderr := runScanWith(deps, "--config", cfg, "scan")
			if code != base || code != exitcode.GateExceeded {
				t.Fatalf("exit %d with the build, %d without\nstdout %s\nstderr %s", code, base, stdout, stderr)
			}
			if opened != 1 || tt.fb.closes != boolInt(tt.openErr == nil) {
				t.Errorf("opened %d, closed %d", opened, tt.fb.closes)
			}
			if strings.Contains(stdout+stderr, "\x1b") {
				t.Errorf("output not escaped: %q", stdout+stderr)
			}
			assertContains(t, "report.md", readState(t, "report.md"), []string{tt.want, "probable"})
			assertAllProbable(t)
		})
	}
}

// TestBuildUsesScanFiles: the build gets the scan's own file list, never
// .git or .creep, and the scan's confined reader, which refuses a path
// outside the repository and a directory.
func TestBuildUsesScanFiles(t *testing.T) {
	files := map[string]string{"app.py": "@flask", "Dockerfile": "FROM scratch\n", "lib/util.py": "x = 1\n", ".git/config": "[core]\n"}
	outside := filepath.Join(t.TempDir(), "abs")
	var problems []string
	probe := func(repo sandbox.Repo) {
		if data, err := repo.Read("lib/util.py"); err != nil || string(data) != files["lib/util.py"] {
			problems = append(problems, fmt.Sprintf("Read = %q, %v", data, err))
		}
		for _, bad := range []string{"../outside.txt", "lib", outside} {
			if _, err := repo.Read(bad); err == nil {
				problems = append(problems, fmt.Sprintf("Read(%q) succeeded", bad))
			}
		}
	}
	fb := &fakeBuilder{app: sandbox.App{Unavailable: sandbox.BuildNoFile}, probe: probe}
	opened := 0
	deps := withBuilder(fakeDeps(&fakeModel{verdict: sqliVulnerable}, calibrate.TierM), fb, nil, &opened)
	if code, _, stderr := runScanWith(deps, "--config", scanRepo(t, files, sandboxOn), "scan"); code != exitcode.GateExceeded {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if want := []string{"Dockerfile", "app.py", "lib/util.py"}; !slices.Equal(fb.repo.Paths, want) {
		t.Fatalf("build paths %q, want %q", fb.repo.Paths, want)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestBuildOnlyWhenEnabled: no build without sandbox.enabled, without a
// usable runtime, or from a project file that sets it (ignored under
// --config here; without --config it is a config error, exit 2:
// TestProjectFileCannotStarveScanIntoPass); a build is cut by the scan deadline,
// and the scan still ends as it would.
func TestBuildOnlyWhenEnabled(t *testing.T) {
	tests := []struct {
		name     string
		user     string
		project  string
		checked  []sandbox.Status
		wait     bool
		wantCode int
		want     string // in stdout+stderr; "" for no sandbox line
	}{
		{"off", "", "", []sandbox.Status{rootlessDocker}, false, exitcode.GateExceeded, ""},
		{"project file", "", sandboxOn, []sandbox.Status{rootlessDocker}, false, exitcode.GateExceeded, ""},
		{"no runtime", sandboxOn, "", []sandbox.Status{missingDocker, missingPodman}, false, exitcode.GateExceeded, "verification unavailable (no_runtime)"},
		{"deadline", sandboxOn + "budget:\n  max_seconds: 1\n", "", []sandbox.Status{rootlessDocker}, true, exitcode.GateExceeded, "verification unavailable (budget)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := &fakeBuilder{wait: tt.wait}
			opened := 0
			deps := withBuilder(fakeDeps(&fakeModel{verdict: sqliVulnerable}, calibrate.TierM), fb, nil, &opened)
			deps.sandbox.detect = withSandbox(deps, tt.checked, nil, nil).sandbox.detect
			files := map[string]string{"app.py": "@flask"}
			if tt.project != "" {
				files["creep.yaml"] = tt.project
			}
			code, stdout, stderr := runScanWith(deps, "--config", scanRepo(t, files, tt.user), "scan")
			if code != tt.wantCode {
				t.Fatalf("exit %d, want %d\n%s", code, tt.wantCode, stderr)
			}
			if tt.want == "" && strings.Contains(stdout+stderr, "sandbox:") || tt.want != "" && !strings.Contains(stdout+stderr, tt.want) {
				t.Errorf("want %q in output:\n%s%s", tt.want, stdout, stderr)
			}
			if wantBuilds := boolInt(tt.wait); fb.builds != wantBuilds || fb.closes != wantBuilds {
				t.Errorf("builds %d, closes %d, want %d", fb.builds, fb.closes, wantBuilds)
			}
		})
	}
}

// TestUnavailableVerificationStaysValid: a reason or detail that is not an
// ID never reaches report.New, which would fail the scan.
func TestUnavailableVerificationStaysValid(t *testing.T) {
	for _, tc := range [][2]string{{"", ""}, {"no build", "x"}, {"build_failed", "a b"}, {"build_failed", "exit_-1"}} {
		v := unavailableVerification(tc[0], tc[1])
		if !report.ValidID(v.Reason) || v.Detail != "" && !report.ValidID(v.Detail) {
			t.Errorf("unavailableVerification(%q, %q) = %+v", tc[0], tc[1], v)
		}
	}
}

var sqliVulnerable = map[string]string{"sql_injection": "vulnerable"}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func readState(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(stateDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// assertAllProbable reads the JSON report: findings exist, none verified.
func assertAllProbable(t *testing.T) {
	t.Helper()
	f, err := os.Open(filepath.Join(stateDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := report.ReadJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("no findings to check")
	}
	for _, fd := range rep.Findings {
		if fd.Status == report.StatusVerified {
			t.Errorf("finding %s is verified, but no PoC ran", fd.ID)
		}
	}
}
