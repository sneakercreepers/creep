package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

// unfitCalibration is fixedCalibration with the verdict of a model that
// flags every safe twin: 32 of the 64 planned tasks right.
func unfitCalibration(ctx context.Context, opts calibrate.CacheOptions) (calibrate.Calibration, error) {
	c, err := fixedCalibration(calibrate.TierS, nil)(ctx, opts)
	c.Fitness = calibrate.Fitness{Reason: calibrate.UnfitBelowChance, Planned: calibrate.ClassScore{
		Score: calibrate.Score{Correct: 32, Total: 64, Lower: 0.381, Upper: 0.619}, SafeTwins: 32, SafeFlagged: 32,
	}}
	return c, err
}

// Protection (#363, ADR 0036): an unfit model is refused with exit 3 and
// the measured numbers before discovery, so no repository file is sent
// and no report is written. The override is a flag only: no config key,
// in the project file or any other layer, can lift it.
func TestScanRefusesUnfitModel(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		args    []string
		code    int
		wantErr string
	}{
		{"refused", "", nil, exitcode.ModelOrSandbox, "model unfit (below_chance): 32 of 64"},
		{"no config key allows it", "calibration:\n  allow_unfit_model: true\n", nil, exitcode.ConfigError, "unknown key"},
		{"not for estimate", "", []string{"estimate", "--allow-unfit-model"}, exitcode.ConfigError, "changes only scan and resume"},
		{"not for mcp", "", []string{"mcp", "--allow-unfit-model"}, exitcode.ConfigError, "changes only scan and resume"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, tt.config)
			m := &fakeModel{verdict: map[string]string{"sql_injection": "vulnerable"}}
			deps := fakeDeps(m, calibrate.TierS)
			deps.calibrate = unfitCalibration
			args := tt.args
			if args == nil {
				args = []string{"scan"}
			}
			code, out, errOut := runScanWith(deps, append(args, "--config", cfg)...)
			if code != tt.code || !strings.Contains(errOut, tt.wantErr) {
				t.Fatalf("exit %d, stderr %q; want %d and %q (stdout %q)", code, errOut, tt.code, tt.wantErr, out)
			}
			if m.calls != 0 {
				t.Errorf("the model got %d calls past the floor", m.calls)
			}
			if _, err := os.Stat(filepath.Join(stateDir, "report.json")); !os.IsNotExist(err) {
				t.Fatalf("a report was written: %v", err)
			}
		})
	}
}

// With --allow-unfit-model the scan runs, the calibration line says the
// model is unfit and every model finding carries unreliable_model in the
// text summary, JSON v1, Markdown and SARIF.
func TestAllowUnfitModelLabelsFindings(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	m := &fakeModel{verdict: map[string]string{"sql_injection": "vulnerable"}}
	deps := fakeDeps(m, calibrate.TierS)
	deps.calibrate = unfitCalibration
	code, out, errOut := runScanWith(deps, "scan", "--allow-unfit-model", "--config", cfg)
	if code == exitcode.ModelOrSandbox || code == exitcode.ConfigError {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{"UNFIT (below_chance", "probable  sqli", "  " + "unreliable_model"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errOut, "warning: model unfit") {
		t.Errorf("stderr lacks the warning: %q", errOut)
	}
	rep, err := readLastReport()
	if err != nil || len(rep.Findings) == 0 {
		t.Fatalf("report: %v, %d findings", err, len(rep.Findings))
	}
	for _, f := range rep.Findings {
		if !f.UnreliableModel {
			t.Errorf("finding %s is not labeled unreliable_model", f.ID)
		}
	}
	for name, want := range map[string]string{"report.json": `"unreliable_model": true`, "report.md": "`unreliable_model`", "report.sarif": `"unreliable_model": true`} {
		data, err := os.ReadFile(filepath.Join(stateDir, name))
		if err != nil || !strings.Contains(string(data), want) {
			t.Errorf("%s lacks %q (%v)", name, want, err)
		}
	}
}
