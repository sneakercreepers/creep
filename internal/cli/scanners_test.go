package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/repofile"
)

const allScanners = "scanners:\n  enabled: [gitleaks, osv-scanner, semgrep]\n"

// placeScanner writes a fake semgrep into dir. It is never run: creep
// only looks for it on PATH.
func placeScanner(t *testing.T, dir string) {
	t.Helper()
	name := "semgrep"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("not a program\n"), 0o700); err != nil { //nolint:gosec // G306: a fake executable in t.TempDir()
		t.Fatal(err)
	}
}

// Acceptance (#10): a missing, refused or not-run scanner never fails a
// scan or makes it incomplete, and the coverage section lists each scanner
// with the classes it would cover, in the JSON report and the terminal.
func TestScanListsOptionalScanners(t *testing.T) {
	tests := []struct {
		name   string
		config string
		setup  func(t *testing.T) string // returns PATH; runs inside the repository
		want   report.ScannerStatus
	}{
		{"not enabled (default)", "", func(t *testing.T) string { return t.TempDir() }, report.ScannerNotEnabled},
		{"enabled and absent", allScanners, func(t *testing.T) string { return t.TempDir() }, report.ScannerMissing},
		{"enabled and present", allScanners, func(t *testing.T) string {
			bin := t.TempDir()
			placeScanner(t, bin)
			return bin
		}, report.ScannerNotRun},
		{"present inside the repository is refused", allScanners, func(t *testing.T) string {
			wd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			placeScanner(t, filepath.Join(wd, "tools"))
			return filepath.Join(wd, "tools")
		}, report.ScannerRefused},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, tt.config)
			t.Setenv("PATH", tt.setup(t))
			code, out, errOut := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--config", cfg)
			if code != exitcode.OK || strings.Contains(out, "INCOMPLETE RUN") {
				t.Fatalf("exit %d, want 0 and a complete run\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
			}
			line := "scanner semgrep: " + string(tt.want) + "; not evaluated: xss, insecure_deserialization, weak_crypto"
			if !strings.Contains(out, line) {
				t.Errorf("stdout lacks %q:\n%s", line, out)
			}
			checkReportScanners(t, tt.want)
		})
	}
}

func checkReportScanners(t *testing.T, semgrep report.ScannerStatus) {
	t.Helper()
	rep, err := readLastReport()
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Coverage.Scanners
	if len(got) != len(repofile.Scanners()) {
		t.Fatalf("report scanners = %+v, want one per scanner", got)
	}
	for _, s := range got {
		if len(s.Classes) == 0 {
			t.Errorf("scanner %s lists no classes", s.Name)
		}
		if s.Name == string(repofile.ScannerSemgrep) && s.Status != semgrep {
			t.Errorf("semgrep status %s, want %s", s.Status, semgrep)
		}
	}
}

// Every scanner maps to classes and every detection state to a report
// status, by explicit switch; an unknown state is refused.
func TestScannerMappingIsExhaustive(t *testing.T) {
	for _, s := range repofile.Scanners() {
		if len(scannerClasses(s)) == 0 {
			t.Errorf("scanner %s maps to no class", s)
		}
	}
	states := map[repofile.ScannerState]report.ScannerStatus{
		repofile.ScannerNotEnabled: report.ScannerNotEnabled, repofile.ScannerMissing: report.ScannerMissing,
		repofile.ScannerRefused: report.ScannerRefused, repofile.ScannerFound: report.ScannerNotRun,
		repofile.ScannerState(200): report.ScannerRefused,
	}
	for st, want := range states {
		if got := scannerStatus(st); got != want {
			t.Errorf("scannerStatus(%d) = %s, want %s", st, got, want)
		}
	}
}
