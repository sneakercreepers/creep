package report

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// #358 (ADR 0037): every format says the calibration measures data-flow
// reasoning on neutral tasks, not the repository's languages, complete or
// incomplete; JSON v1 carries it additively, validates and reads back, and
// a v1 report written before #358 (no field) still reads.
func TestCalibrationScopeInEveryFormat(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		got := render(t, newTestReport(t, sampleInput(t, incomplete)))
		for ext, want := range map[string]string{
			"md":    "The " + CalibrationScopeNote + ".",
			"sarif": `"creep/calibration-scope"`,
			"json":  `"calibration_scope": "language_neutral"`,
		} {
			if !strings.Contains(string(got[ext]), want) {
				t.Errorf("incomplete=%v: %s lacks %q", incomplete, ext, want)
			}
		}
		assertValid(t, loadJSON(t, filepath.Join("..", "..", "docs", "schemas", "report-v1.json")), got["json"])
		back, err := ReadJSON(bytes.NewReader(got["json"]))
		if err != nil || back.Coverage.CalibrationScope != CalibrationScope {
			t.Fatalf("ReadJSON = %v, scope %+v", err, back)
		}
		old := bytes.Replace(got["json"], []byte(`,
    "calibration_scope": "language_neutral"`), nil, 1)
		if bytes.Equal(old, got["json"]) {
			t.Fatal("could not strip calibration_scope to build a pre-#358 report")
		}
		if _, err := ReadJSON(bytes.NewReader(old)); err != nil {
			t.Errorf("a v1 report without calibration_scope no longer reads: %v", err)
		}
	}
}
