package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestStabilityChecked: report.New refuses stability no --stability run
// makes, a label that does not match its counts, and stability on a
// finding that is neither probable nor verified.
func TestStabilityChecked(t *testing.T) {
	tests := []struct {
		name   string
		status Status
		s      *Stability
		ok     bool
	}{
		{"none", StatusProbable, nil, true},
		{"unstable probable", StatusProbable, NewStability(1, 3), true},
		{"stable verified", StatusVerified, NewStability(5, 5), true},
		{"seen in no run", StatusProbable, NewStability(0, 2), true},
		{"discarded", StatusDiscarded, NewStability(1, 3), false},
		{"not evaluated", StatusNotEvaluated, NewStability(1, 3), false},
		{"one run", StatusProbable, NewStability(1, 1), false},
		{"over the bound", StatusProbable, NewStability(6, MaxStabilityRuns+1), false},
		{"seen over runs", StatusProbable, &Stability{Runs: 3, Seen: 4}, false},
		{"seen negative", StatusProbable, &Stability{Runs: 3, Seen: -1, Unstable: true}, false},
		{"unstable label on a stable count", StatusProbable, &Stability{Runs: 3, Seen: 3, Unstable: true}, false},
		{"stable label on an unstable count", StatusProbable, &Stability{Runs: 3, Seen: 2}, false},
	}
	for _, tt := range tests {
		f := Finding{ID: "f1", Class: "sqli", Status: tt.status, Path: "a.py", Line: 1, Stability: tt.s}
		_, err := New(Input{Findings: []Finding{f}})
		if (err == nil) != tt.ok || (err != nil && !errors.Is(err, ErrInvalid)) {
			t.Errorf("%s: err = %v, want ok %v", tt.name, err, tt.ok)
		}
	}
}

// TestStabilityInFormats (#37 acceptance): every format says unstable
// discovery in its own words, apart from an intermittent PoC on the same
// finding, and JSON carries the counts additively under v1.
func TestStabilityInFormats(t *testing.T) {
	in := sampleInput(t, false)
	in.Findings[3].PoC = PoCRate{3, 5}
	in.Findings[3].Stability = NewStability(2, 3)
	got := render(t, newTestReport(t, in))
	for ext, want := range map[string][]string{
		"md":    {"`verified in 3/5 runs, intermittent`, `unstable discovery: seen in 2 of 3 runs`"},
		"sarif": {"(verified, verified in 3/5 runs, intermittent, unstable discovery: seen in 2 of 3 runs)", `"poc_runs": 5`, `"runs": 3`, `"seen": 2`, `"unstable": true`},
		"json":  {`"stability": {`, `"runs": 3`, `"seen": 2`, `"unstable": true`},
	} {
		for _, w := range want {
			if !strings.Contains(string(got[ext]), w) {
				t.Errorf("%s lacks %q:\n%s", ext, w, got[ext])
			}
		}
	}
	if strings.Contains(string(got["json"]), "intermittent") {
		t.Error("JSON v1 carries the PoC rate; it must stay out (ADR 0020)")
	}
	if text := NewStability(3, 3).Text(); text != "stable discovery: seen in 3 of 3 runs" {
		t.Errorf("stable text %q", text)
	}
}

// ReadJSON checks stability as New does, so creep why refuses a planted
// report that labels a discarded finding or lies about its counts.
func TestReadJSONChecksStability(t *testing.T) {
	r, err := New(Input{Findings: []Finding{{ID: "f1", Class: "sqli", Status: StatusProbable, Path: "a.py", Line: 1, Stability: NewStability(1, 2)}}})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := WriteJSON(&b, r); err != nil {
		t.Fatal(err)
	}
	back, err := ReadJSON(bytes.NewReader(b.Bytes()))
	if err != nil || *back.Findings[0].Stability != *NewStability(1, 2) {
		t.Fatalf("ReadJSON = %+v, %v", back, err)
	}
	for _, planted := range [][]byte{
		bytes.Replace(b.Bytes(), []byte(`"status": "probable"`), []byte(`"status": "discarded"`), 1),
		bytes.Replace(b.Bytes(), []byte(`"unstable": true`), []byte(`"unstable": false`), 1),
		bytes.Replace(b.Bytes(), []byte(`"runs": 2`), []byte(`"runs": 9`), 1),
	} {
		if _, err := ReadJSON(bytes.NewReader(planted)); !errors.Is(err, ErrInvalid) {
			t.Errorf("a planted stability read back: %v", err)
		}
	}
}
