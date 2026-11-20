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
	"time"

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
// .git, .creep or a link, and the scan's confined reader. Files beside
// the repository exist and hold a marker, so a reader that is not
// confined to the root would hand them to the build: through "..", an
// absolute path, a sibling directory or a link pointing out.
func TestBuildUsesScanFiles(t *testing.T) {
	const marker = "OUTSIDE-THE-REPOSITORY"
	files := map[string]string{"app.py": "@flask", "Dockerfile": "FROM scratch\n", "lib/util.py": "x = 1\n", ".git/config": "[core]\n"}
	cfg := scanRepo(t, files, sandboxOn)
	repo, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(repo), "outside.txt")
	sibling := filepath.Join(filepath.Dir(repo), "sibling", "secret.txt")
	writeBeside(t, outside, marker)
	writeBeside(t, sibling, marker)
	bad := []string{"../outside.txt", "../sibling/secret.txt", outside, "lib"}
	if os.Symlink(outside, filepath.Join(repo, "link.txt")) == nil {
		bad = append(bad, "link.txt")
	}
	var problems []string
	probe := func(r sandbox.Repo) {
		if data, err := r.Read("lib/util.py"); err != nil || string(data) != files["lib/util.py"] {
			problems = append(problems, fmt.Sprintf("Read = %q, %v", data, err))
		}
		for _, p := range bad {
			if data, err := r.Read(p); err == nil || strings.Contains(string(data), marker) {
				problems = append(problems, fmt.Sprintf("Read(%q) = %q, %v", p, data, err))
			}
		}
	}
	fb := &fakeBuilder{app: sandbox.App{Unavailable: sandbox.BuildNoFile}, probe: probe}
	opened := 0
	deps := withBuilder(fakeDeps(&fakeModel{verdict: sqliVulnerable}, calibrate.TierM), fb, nil, &opened)
	// A link pointing out of the repository is listed not_regular, so the
	// run may end incomplete; it must still reach the build.
	if code, _, stderr := runScanWith(deps, "--config", cfg, "scan"); code != exitcode.GateExceeded && code != exitcode.Incomplete {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if want := []string{"Dockerfile", "app.py", "lib/util.py"}; !slices.Equal(fb.repo.Paths, want) {
		t.Fatalf("build paths %q, want %q", fb.repo.Paths, want)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// writeBeside writes a file at path, outside the repository.
func writeBeside(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil { //nolint:gosec // G703: beside the test's own t.TempDir()
		t.Fatal(err)
	}
}

// TestBuildOnlyWhenEnabled: no build without sandbox.enabled, without a
// usable runtime, or from a project file that sets it (ignored under
// --config here; without --config it is a config error, exit 2:
// TestProjectFileCannotStarveScanIntoPass). The scan deadline is read from
// the sandbox clock, so these cases do not depend on how long the scan
// takes: a deadline already past opens no sandbox, and one that passes
// during the build ends it as budget. The scan always exits as it would.
func TestBuildOnlyWhenEnabled(t *testing.T) {
	const budget = "budget:\n  max_seconds: 60\n"
	tests := []struct {
		name     string
		user     string
		project  string
		checked  []sandbox.Status
		elapsed  time.Duration // what the clock says after the deadline is set; 0 is the real clock
		builds   int
		wantCode int
		want     string // in stdout+stderr; "" for no sandbox line
	}{
		{"off", "", "", []sandbox.Status{rootlessDocker}, 0, 0, exitcode.GateExceeded, ""},
		{"project file", "", sandboxOn, []sandbox.Status{rootlessDocker}, 0, 0, exitcode.GateExceeded, ""},
		{"no runtime", sandboxOn, "", []sandbox.Status{missingDocker, missingPodman}, 0, 0, exitcode.GateExceeded, "verification unavailable (no_runtime)"},
		{"deadline before the build", sandboxOn + budget, "", []sandbox.Status{rootlessDocker}, time.Minute, 0, exitcode.GateExceeded, "verification unavailable (budget)"},
		{"deadline during the build", sandboxOn + budget, "", []sandbox.Status{rootlessDocker}, time.Minute - time.Millisecond, 1, exitcode.GateExceeded, "verification unavailable (budget)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := &fakeBuilder{wait: true}
			opened := 0
			deps := withBuilder(fakeDeps(&fakeModel{verdict: sqliVulnerable}, calibrate.TierM), fb, nil, &opened)
			deps.sandbox.detect = withSandbox(deps, tt.checked, nil, nil).sandbox.detect
			if tt.elapsed > 0 {
				deps.sandbox.now = steppedClock(tt.elapsed)
			}
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
			if opened != tt.builds || fb.builds != tt.builds || fb.closes != tt.builds {
				t.Errorf("opened %d, builds %d, closes %d, want %d", opened, fb.builds, fb.closes, tt.builds)
			}
		})
	}
}

// steppedClock reads a fixed time once, when the scan sets its deadline,
// and that time plus elapsed on every later read.
func steppedClock(elapsed time.Duration) func() time.Time {
	start, reads := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC), 0
	return func() time.Time {
		if reads++; reads == 1 {
			return start
		}
		return start.Add(elapsed)
	}
}

// TestCtrlCClosesTheSandbox (#23 F2): Ctrl+C while the sandbox is open
// cancels the build instead of killing creep, so the sandbox is closed and
// the scan reports interrupted and exits as it would.
func TestCtrlCClosesTheSandbox(t *testing.T) {
	var interrupt context.CancelFunc
	fb := &fakeBuilder{wait: true, probe: func(sandbox.Repo) { interrupt() }}
	opened := 0
	deps := withBuilder(fakeDeps(&fakeModel{verdict: sqliVulnerable}, calibrate.TierM), fb, nil, &opened)
	deps.sandbox.interrupt = func(ctx context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(ctx)
		interrupt = cancel
		return ctx, cancel
	}
	code, stdout, stderr := runScanWith(deps, "--config", scanRepo(t, map[string]string{"app.py": "@flask"}, sandboxOn), "scan")
	if code != exitcode.GateExceeded {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	if fb.builds != 1 || fb.closes != 1 {
		t.Errorf("builds %d, closes %d", fb.builds, fb.closes)
	}
	assertContains(t, "stdout", stdout, []string{"verification unavailable (interrupted)"})
}

// TestVerificationReasonsClosed: every reason the sandbox or the scan can
// give is in the report's closed set, and anything else becomes
// sandbox_error instead of failing the scan.
func TestVerificationReasonsClosed(t *testing.T) {
	reasons := []string{verifyNotChecked, verifyNoRuntime, verifySandboxError, verifyInterrupted, verifyDeadline}
	for _, r := range sandbox.BuildReasons() {
		reasons = append(reasons, string(r))
	}
	for _, r := range reasons {
		if v := unavailableVerification(r, ""); v.Reason != r || !report.ValidVerificationReason(r) {
			t.Errorf("reason %q: %+v", r, v)
		}
	}
	if v := unavailableVerification("made_up", "x"); v.Reason != verifySandboxError {
		t.Errorf("unknown reason kept: %+v", v)
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
