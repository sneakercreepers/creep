package cli

import (
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

// creep mcp can never scan past the fitness floor: the flag is refused
// before the server starts (TestScanRefusesUnfitModel), and mcpScanOptions
// clears it again for every MCP scan, so dropping either guard fails here.
func TestMCPScanClearsAllowUnfit(t *testing.T) {
	o := defaultOptions()
	o.allowUnfit = true
	if mcpScanOptions(o).allowUnfit {
		t.Fatal("an MCP scan keeps --allow-unfit-model")
	}
	if err := checkUnfitFlag("mcp", o); err == nil {
		t.Fatal("creep mcp accepts --allow-unfit-model")
	}
}

// A resume passes the floor again (#363, ADR 0036). An unfit run got past
// calibration only with --allow-unfit-model: resumed without it, it is
// refused with exit 3 and nothing sent; resumed with it, it finishes with
// every finding labeled. The flag is not in the resume header, so both
// resumes see the same header and only the floor decides.
func TestResumeKeepsFitnessFloor(t *testing.T) {
	unfitDeps := func(m *cutModel) scanDeps {
		deps := tierMDeps(m)
		deps.calibrate = unfitCalibration
		return deps
	}
	tests := []struct {
		name  string
		flags []string
		code  int
	}{
		{"refused without the flag", nil, exitcode.ModelOrSandbox},
		{"finishes with the flag", []string{"--allow-unfit-model"}, exitcode.GateExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, id := killedRun(t, resumeFiles(t), "", unfitDeps, "--allow-unfit-model")
			m := newCutModel(sqliVulnerable, "", 0)
			code, out, errOut := runScanWith(unfitDeps(m), append([]string{"resume", id, "--config", cfg}, tt.flags...)...)
			if code != tt.code {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, tt.code, out, errOut)
			}
			if tt.code == exitcode.ModelOrSandbox {
				if len(m.bodies) != 0 || !strings.Contains(errOut, "model unfit (below_chance)") {
					t.Fatalf("%d calls sent, stderr %q", len(m.bodies), errOut)
				}
				return
			}
			rep, err := readLastReport()
			if err != nil || len(rep.Findings) == 0 {
				t.Fatalf("report: %v", err)
			}
			for _, f := range rep.Findings {
				if !f.UnreliableModel {
					t.Errorf("resumed finding %s is not labeled unreliable_model", f.ID)
				}
			}
		})
	}
}
