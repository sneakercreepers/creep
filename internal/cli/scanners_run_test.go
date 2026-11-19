package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/repofile"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/scanrun"
)

// placeTool writes a file named like the scanner into a new directory
// outside the repository and returns it as PATH. The runner is faked, so
// nothing executes it.
func placeTool(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("not a program\n"), 0o700); err != nil { //nolint:gosec // G306: a fake executable in t.TempDir()
		t.Fatal(err)
	}
	return dir
}

// TestScanRunsOptionalScanners covers ADR 0013 through creep scan: an
// evaluated scanner adds probable findings without changing the exit
// code; a failed one makes the run incomplete (exit 4). The runner gets
// the final path and the repository, and the job is never started for a
// scanner the project file alone enabled (see config tests).
func TestScanRunsOptionalScanners(t *testing.T) {
	findings := []scanrun.Finding{{Path: "app.py", Line: 3, Key: strings.Repeat("ab", 12)}} // a 24-digit hex key, built so it is not secret-shaped source
	tests := []struct {
		name     string
		result   scanrun.Result
		wantCode int
		status   report.ScannerStatus
		findings int
		line     string
	}{
		{"evaluated with findings", scanrun.Result{Outcome: scanrun.Evaluated, Findings: findings}, exitcode.OK, report.ScannerEvaluated, 1, "scanner gitleaks: evaluated; evaluated: hardcoded_secret"},
		{"evaluated clean", scanrun.Result{Outcome: scanrun.Evaluated}, exitcode.OK, report.ScannerEvaluated, 0, "scanner gitleaks: evaluated"},
		{"failed", scanrun.Result{Outcome: scanrun.Failed, Failure: scanrun.FailTimeout}, exitcode.Incomplete, report.ScannerFailed, 0, "scanner gitleaks: failed; not evaluated: hardcoded_secret"},
		{"refused at run time", scanrun.Result{Outcome: scanrun.Refused}, exitcode.OK, report.ScannerRefused, 0, "scanner gitleaks: refused"},
		{"unknown outcome fails closed", scanrun.Result{Outcome: scanrun.Outcome(200)}, exitcode.Incomplete, report.ScannerFailed, 0, "scanner gitleaks: failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "scanners:\n  enabled: [gitleaks]\n")
			t.Setenv("PATH", placeTool(t, "gitleaks"))
			repo, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			deps := fakeDeps(&fakeModel{}, calibrate.TierM)
			var jobs []scanrun.Job
			deps.runScanner = func(_ context.Context, job scanrun.Job) scanrun.Result {
				jobs = append(jobs, job)
				return tt.result
			}
			code, out, errOut := runScanWith(deps, "scan", "--config", cfg)
			if code != tt.wantCode || !strings.Contains(out, tt.line) {
				t.Fatalf("exit %d (want %d), stdout lacks %q\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, tt.line, out, errOut)
			}
			if len(jobs) != 1 || jobs[0].Scanner != repofile.ScannerGitleaks || !filepath.IsAbs(jobs[0].Bin) || jobs[0].Repo != repo {
				t.Fatalf("jobs = %+v, want one gitleaks job with a final path in repository %s", jobs, repo)
			}
			checkScannerReport(t, tt.status, tt.findings, tt.wantCode == exitcode.Incomplete)
		})
	}
}

func checkScannerReport(t *testing.T, status report.ScannerStatus, findings int, incomplete bool) {
	t.Helper()
	rep, err := readLastReport()
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Coverage.Scanners[0]; got.Status != status {
		t.Errorf("gitleaks status %s, want %s", got.Status, status)
	}
	n := 0
	for _, f := range rep.Findings {
		if f.Class == "hardcoded_secret" {
			n++
			if !strings.HasPrefix(f.ID, "gitleaks-") || f.Status != report.StatusProbable || f.Path != "app.py" {
				t.Errorf("scanner finding %+v", f)
			}
		}
	}
	if n != findings {
		t.Errorf("%d scanner findings, want %d", n, findings)
	}
	if rep.Run.Incomplete != incomplete || (incomplete && rep.Run.Reason != reasonScannerFailed) {
		t.Errorf("run = %+v, want incomplete %v with reason %s", rep.Run, incomplete, reasonScannerFailed)
	}
}

func TestRunStatusIsExhaustive(t *testing.T) {
	want := map[scanrun.Outcome]report.ScannerStatus{
		scanrun.NotRun: report.ScannerNotRun, scanrun.Refused: report.ScannerRefused,
		scanrun.Failed: report.ScannerFailed, scanrun.Evaluated: report.ScannerEvaluated,
		scanrun.Outcome(200): report.ScannerFailed,
	}
	for o, w := range want {
		if got := runStatus(o); got != w {
			t.Errorf("runStatus(%d) = %s, want %s", o, got, w)
		}
	}
	for _, s := range []repofile.Scanner{repofile.ScannerGitleaks, repofile.ScannerOSV} {
		class, _ := scannerFindingClass(s)
		if _, ok := classSeverity[class]; !ok || !strings.Contains(strings.Join(scannerClasses(s), ","), class) {
			t.Errorf("scanner %s finding class %q has no severity or is not one of its classes", s, class)
		}
	}
}
