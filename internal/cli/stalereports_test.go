package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

const plantedSARIF = `{"version":"2.1.0","runs":[{"results":[]}]}`

// Regression (pentest P5): a report the repository committed in .creep is
// gone after a scan, whether or not this run writes that format and even
// when the run fails after opening the state directory.
func TestScanRemovesPlantedReports(t *testing.T) {
	tests := []struct {
		name     string
		extra    string
		calErr   error
		wantCode int
		want     []string // report files left after the run
	}{
		{"narrowed formats", "report:\n  formats: [json]\n", nil, exitcode.GateExceeded, []string{"report.json"}},
		{"no formats", "report:\n  formats: []\n", nil, exitcode.GateExceeded, nil},
		{"model fails", "", errors.New("model said 500"), exitcode.ModelOrSandbox, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{
				"app.py":              "@flask",
				".creep/report.sarif": plantedSARIF,
				".creep/report.md":    "# no findings\n",
			}, tt.extra)
			deps := fakeDeps(&fakeModel{verdict: map[string]string{"sql_injection": "vulnerable"}}, calibrate.TierM)
			deps.calibrate = fixedCalibration(calibrate.TierM, tt.calErr)
			code, out, errOut := runScanWith(deps, "scan", "--config", cfg)
			if code != tt.wantCode {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, tt.wantCode, out, errOut)
			}
			if got := reportFiles(t); strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("report files after the run = %v, want %v", got, tt.want)
			}
		})
	}
}

// A planted link is removed, not followed: its target outside .creep keeps
// its content.
func TestScanRemovesPlantedReportLink(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask", ".creep/keep": ""}, "report:\n  formats: [json]\n")
	target := filepath.Join(t.TempDir(), "outside.sarif")
	mustWrite(t, target, plantedSARIF)
	if err := os.Symlink(target, filepath.Join(stateDir, "report.sarif")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if code, out, errOut := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--config", cfg); code != exitcode.OK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if _, err := os.Lstat(filepath.Join(stateDir, "report.sarif")); !os.IsNotExist(err) {
		t.Fatalf("planted link still there: %v", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != plantedSARIF {
		t.Fatalf("link target changed: %q, %v", data, err)
	}
}

// A report name that cannot be removed (a non-empty directory) stops the
// scan before any model call.
func TestScanRefusesUnremovableReport(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask", ".creep/report.md/x": "x"}, "")
	m := &fakeModel{}
	code, _, errOut := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--config", cfg)
	if code != exitcode.ConfigError || !strings.Contains(errOut, "remove stale report.md") || m.calls != 0 {
		t.Fatalf("exit %d after %d calls, stderr %q", code, m.calls, errOut)
	}
}

// reportFiles lists the report files in .creep.
func reportFiles(t *testing.T) []string {
	t.Helper()
	var got []string
	for _, name := range []string{"report.json", "report.md", "report.sarif"} {
		if _, err := os.Lstat(filepath.Join(stateDir, name)); err == nil {
			got = append(got, name)
		}
	}
	return got
}
