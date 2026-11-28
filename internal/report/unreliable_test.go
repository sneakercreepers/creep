package report

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// #363 (ADR 0036): a finding from a model scanned past the fitness floor
// says unreliable_model in Markdown, SARIF (message and properties) and
// JSON v1, additively, and the label reads back; an unlabeled finding
// carries no trace of it.
func TestUnreliableModelInFormats(t *testing.T) {
	in := sampleInput(t, false)
	clean := render(t, newTestReport(t, in))
	for ext, out := range clean {
		if strings.Contains(string(out), LabelUnreliableModel) {
			t.Errorf("%s names %s with no label set", ext, LabelUnreliableModel)
		}
	}
	for i := range in.Findings {
		in.Findings[i].UnreliableModel = true
	}
	got := render(t, newTestReport(t, in))
	for ext, want := range map[string][]string{
		"md":    {", `unreliable_model`"},
		"sarif": {", unreliable_model)", `"unreliable_model": true`},
		"json":  {`"unreliable_model": true`},
	} {
		for _, w := range want {
			if !strings.Contains(string(got[ext]), w) {
				t.Errorf("%s lacks %q:\n%s", ext, w, got[ext])
			}
		}
	}
	assertValid(t, loadJSON(t, filepath.Join("..", "..", "docs", "schemas", "report-v1.json")), got["json"])
	back, err := ReadJSON(bytes.NewReader(got["json"]))
	if err != nil || !back.Findings[0].UnreliableModel {
		t.Fatalf("ReadJSON = %v, label %v", err, back != nil && back.Findings[0].UnreliableModel)
	}
}

// #363 audit: a run scanned past the floor that has no findings still
// says so at run level in every format and validates against the schema,
// so an empty finding list never reads as a clean result.
func TestUnreliableModelRunWithNoFindings(t *testing.T) {
	in := sampleInput(t, false)
	in.Findings = nil
	in.UnreliableModel = true
	got := render(t, newTestReport(t, in))
	for ext, want := range map[string][]string{
		"md":    {"> **" + UnreliableModelNote + "**"},
		"sarif": {`"creep/unreliable-model"`, `"unreliable_model": true`},
		"json":  {`"unreliable_model": true`},
	} {
		for _, w := range want {
			if !strings.Contains(string(got[ext]), w) {
				t.Errorf("%s lacks %q:\n%s", ext, w, got[ext])
			}
		}
	}
	assertValid(t, loadJSON(t, filepath.Join("..", "..", "docs", "schemas", "report-v1.json")), got["json"])
	back, err := ReadJSON(bytes.NewReader(got["json"]))
	if err != nil || len(back.Findings) != 0 || !back.Run.UnreliableModel {
		t.Fatalf("ReadJSON = %v, run %+v", err, back)
	}
}
