package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
)

// #363 audit (ADR 0036): a run past the fitness floor that finds nothing
// still says unreliable_model at run level in the text summary, JSON v1,
// Markdown and SARIF, so no format reads as a clean result.
func TestAllowUnfitModelMarksCleanRun(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "print(1)\n"}, "")
	deps := fakeDeps(&fakeModel{}, calibrate.TierS)
	deps.calibrate = unfitCalibration
	code, out, errOut := runScanWith(deps, "scan", "--allow-unfit-model", "--config", cfg)
	if code != exitcode.OK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, report.UnreliableModelNote) {
		t.Errorf("stdout lacks the run marker:\n%s", out)
	}
	rep := lastReport(t)
	if len(rep.Findings) != 0 || !rep.Run.UnreliableModel {
		t.Fatalf("%d findings, run marker %v; want none and set", len(rep.Findings), rep.Run.UnreliableModel)
	}
	for name, want := range map[string]string{
		"report.json":  `"unreliable_model": true`,
		"report.md":    report.UnreliableModelNote,
		"report.sarif": `"creep/unreliable-model"`,
	} {
		data, err := os.ReadFile(filepath.Join(stateDir, name))
		if err != nil || !strings.Contains(string(data), want) {
			t.Errorf("%s lacks %q (%v)", name, want, err)
		}
	}
}

// A fit model's clean run carries no run marker in any format.
func TestFitModelRunHasNoMarker(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "print(1)\n"}, "")
	code, out, errOut := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierS), "scan", "--config", cfg)
	if code != exitcode.OK || strings.Contains(out, "UNRELIABLE MODEL") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for name, data := range readReports(t) {
		if strings.Contains(data, report.LabelUnreliableModel) {
			t.Errorf("%s names %s on a fit run", name, report.LabelUnreliableModel)
		}
	}
}

// A baseline written past the floor would accept an unreliable run's
// findings for every later scan, so the combination is a usage error.
func TestAllowUnfitModelRefusesBaselineWrite(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	m := &fakeModel{}
	deps := fakeDeps(m, calibrate.TierS)
	deps.calibrate = unfitCalibration
	base := filepath.Join(t.TempDir(), "baseline.json")
	code, out, errOut := runScanWith(deps, "scan", "--allow-unfit-model", "--baseline", base, "--baseline-write", "--config", cfg)
	if code != exitcode.ConfigError || !strings.Contains(errOut, "--baseline-write") || m.calls != 0 {
		t.Fatalf("exit %d after %d calls\n%s\n%s", code, m.calls, out, errOut)
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Errorf("baseline written: %v", err)
	}
}

// A --stability run past the floor never feeds the model's stability
// record, which later fit scans read.
func TestUnfitRunWritesNoStabilityRecord(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	cache := &stabilityCache{}
	deps := sampledDeps(newSampledModel("vulnerable", "not_vulnerable", "vulnerable"), cache)
	deps.calibrate = unfitCalibration
	code, out, errOut := runScanWith(deps, "scan", "--stability", "3", "--allow-unfit-model", "--config", cfg)
	if code != exitcode.GateExceeded || !strings.Contains(out, "unstable discovery") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if cache.records != 0 {
		t.Fatalf("unfit run wrote %d stability records: %+v", cache.records, cache.record)
	}
}
