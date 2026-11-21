package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/state"
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

// Regression (#209): report names a repository planted as non-empty
// directories cannot be removed or written, yet the run still prints its
// result and incomplete mark, writes the formats it can, names each lost
// file on stderr and never exits 0: it keeps its own code, or 2 when clean.
func TestScanUnwritableReports(t *testing.T) {
	tests := []struct {
		name     string
		planted  []string // report names planted as directories
		extra    string
		args     []string
		model    *fakeModel
		wantCode int
		want     []string // in stdout
		lost     []string // named on stderr
		written  []string // report files written
	}{
		{"clean run exits 2", []string{"report.json", "report.md", "report.sarif"}, "", nil, &fakeModel{},
			exitcode.ConfigError, []string{"findings: 0 verified"}, []string{"report.json", "report.md", "report.sarif"}, nil},
		{"incomplete run keeps 4", []string{"report.json", "report.md", "report.sarif"}, "", nil,
			&fakeModel{fail: map[string]error{"ssrf": errors.New("connection reset")}},
			exitcode.Incomplete, []string{"INCOMPLETE RUN (reason send_failed)"}, []string{"report.json", "report.md", "report.sarif"}, nil},
		{"gate run keeps 1", []string{"report.md"}, "", nil, &fakeModel{verdict: map[string]string{"sql_injection": "vulnerable"}},
			exitcode.GateExceeded, []string{"reports: .creep/report.json .creep/report.sarif"}, []string{"report.md"}, []string{"report.json", "report.sarif"}},
		{"format not configured", []string{"report.sarif"}, "report:\n  formats: [json]\n", nil, &fakeModel{},
			exitcode.ConfigError, []string{"reports: .creep/report.json"}, []string{"remove stale report.sarif"}, []string{"report.json"}},
		{"json on stdout", []string{"report.json"}, "", []string{"--format", "json"}, &fakeModel{},
			exitcode.ConfigError, []string{`"schema_version"`}, []string{"report.json not written"}, []string{"report.md", "report.sarif"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"app.py": "@flask"}
			for _, name := range tt.planted {
				files[".creep/"+name+"/x"] = "x"
			}
			cfg := scanRepo(t, files, tt.extra)
			args := append([]string{"scan", "--config", cfg}, tt.args...)
			code, out, errOut := runScanWith(fakeDeps(tt.model, calibrate.TierM), args...)
			if code != tt.wantCode || tt.model.calls == 0 {
				t.Fatalf("exit %d after %d calls, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.model.calls, tt.wantCode, out, errOut)
			}
			assertContains(t, "stdout", out, tt.want)
			assertContains(t, "stderr", errOut, tt.lost)
			var regular []string
			for _, name := range reportFiles(t) {
				if info, err := os.Lstat(filepath.Join(stateDir, name)); err == nil && info.Mode().IsRegular() {
					regular = append(regular, name)
				}
			}
			if strings.Join(regular, ",") != strings.Join(tt.written, ",") {
				t.Fatalf("reports written = %v, want %v", regular, tt.written)
			}
		})
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

// Regression (#209 I2): reports go through the handle the state store
// checked, never .creep reopened by path, so a directory swapped in under
// the name after the store opened gets nothing.
func TestWriteReportsUsesStoreRoot(t *testing.T) {
	isolateUserConfig(t)
	t.Chdir(t.TempDir())
	store, err := state.OpenUser(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := os.Rename(stateDir, "checked"); err != nil {
		t.Skipf("cannot rename an open directory here: %v", err)
	}
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rep, err := report.New(report.Input{})
	if err != nil {
		t.Fatal(err)
	}
	written, failed := writeReports(store.Root(), []string{"json", "markdown"}, rep)
	if len(failed) != 0 || len(written) != 2 {
		t.Fatalf("written %v, failed %v", written, failed)
	}
	if got := reportFiles(t); len(got) != 0 {
		t.Fatalf("reports written into the swapped-in directory: %v", got)
	}
	if _, err := os.Lstat(filepath.Join("checked", "report.json")); err != nil {
		t.Fatalf("report not in the checked directory: %v", err)
	}
}
