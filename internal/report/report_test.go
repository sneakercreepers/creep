package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/state"
)

var completeRun = state.Summary{Ended: true, Outcome: state.OutcomeComplete}

func TestNewRejectsInvalidInput(t *testing.T) {
	ok := Finding{ID: "f1", Class: "sqli", Status: StatusVerified, Path: "a.py", Line: 1}
	tests := []struct {
		name string
		in   Input
	}{
		{"unknown status", Input{Findings: []Finding{{ID: "f1", Class: "sqli", Status: "maybe", Path: "a.py"}}}},
		{"free-text ID", Input{Findings: []Finding{{ID: "f 1; rm", Class: "sqli", Status: StatusVerified, Path: "a.py"}}}},
		{"duplicate ID", Input{Findings: []Finding{ok, ok}}},
		{"class with markup", Input{Findings: []Finding{{ID: "f1", Class: "<b>", Status: StatusVerified, Path: "a.py"}}}},
		{"empty path", Input{Findings: []Finding{{ID: "f1", Class: "sqli", Status: StatusVerified}}}},
		{"negative line", Input{Findings: []Finding{{ID: "f1", Class: "sqli", Status: StatusVerified, Path: "a", Line: -1}}}},
		{"free-text reason", Input{Findings: []Finding{{ID: "f1", Class: "sqli", Status: StatusNotEvaluated, Path: "a", Reason: "x\x1b[2J"}}}},
		{"confidence over 100", Input{Findings: []Finding{{ID: "f1", Class: "sqli", Status: StatusProbable, Path: "a", Confidence: 101}}}},
		{"negative confidence", Input{Findings: []Finding{{ID: "f1", Class: "sqli", Status: StatusProbable, Path: "a", Confidence: -1}}}},
		{"evidence line 0", Input{Findings: []Finding{{ID: "f1", Class: "sqli", Status: StatusProbable, Path: "a", Evidence: []LineRange{{0, 1}}}}}},
		{"evidence backwards", Input{Findings: []Finding{{ID: "f1", Class: "sqli", Status: StatusProbable, Path: "a", Evidence: []LineRange{{5, 4}}}}}},
		{"unknown class status", Input{Classes: []ClassCoverage{{Class: "sqli", Status: "done"}}}},
		{"duplicate class", Input{Classes: []ClassCoverage{{Class: "sqli", Status: ClassCovered}, {Class: "sqli", Status: ClassCovered}}}},
		{"detected over tasks", Input{Classes: []ClassCoverage{{Class: "sqli", Status: ClassCovered, Detected: 3, Tasks: 2}}}},
		{"negative tasks", Input{Classes: []ClassCoverage{{Class: "sqli", Status: ClassCovered, Tasks: -1}}}},
		{"unknown skip reason", Input{NotEvaluated: []NotEvaluated{{Path: "a", Reason: "timeout"}}}},
		{"empty skip reason", Input{NotEvaluated: []NotEvaluated{{Path: "a"}}}},
		{"scanner name with markup", Input{Scanners: []ScannerCoverage{{Name: "<b>semgrep", Status: ScannerMissing, Classes: []string{"xss"}}}}},
		{"duplicate scanner", Input{Scanners: []ScannerCoverage{
			{Name: "semgrep", Status: ScannerMissing, Classes: []string{"xss"}}, {Name: "semgrep", Status: ScannerNotRun, Classes: []string{"xss"}},
		}}},
		{"unknown scanner status", Input{Scanners: []ScannerCoverage{{Name: "semgrep", Status: "ran", Classes: []string{"xss"}}}}},
		{"scanner without classes", Input{Scanners: []ScannerCoverage{{Name: "semgrep", Status: ScannerMissing}}}},
		{"scanner class with escapes", Input{Scanners: []ScannerCoverage{{Name: "semgrep", Status: ScannerMissing, Classes: []string{"x\x1b[2J"}}}}},
		{"framework with markup", Input{NoRoutesIn: []string{"Flask", "**Django**"}}},
		{"empty framework name", Input{NoRoutesIn: []string{""}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.in); !errors.Is(err, ErrInvalid) {
				t.Errorf("New() error = %v, want ErrInvalid", err)
			}
		})
	}
}

// Acceptance (#177): a finding path that is absolute, has a drive letter or
// a backslash, or is not clean could point a SARIF location outside
// %SRCROOT%, so New refuses it; odd but clean repository names pass.
func TestNewFindingPaths(t *testing.T) {
	tests := []struct {
		path string
		ok   bool
	}{
		{"/abs", false},
		{"/", false},
		{"C:/x", false},
		{"c:x", false},
		{`C:\x`, false},
		{`\\server\share\x.py`, false},
		{"a:b.py", false}, // a drive letter to Windows
		{"a/../b", false},
		{"../x", false},
		{"..", false},
		{"./x", false},
		{".", false},
		{"a/./b", false},
		{`a\b`, false},
		{"a//b", false},
		{"a/", false},
		{"", false},
		{"a/b.go", true},
		{"dir with space/a b.py", true},
		{"a#b.py", true},
		{"100%.py", true},
		{"ünï/日本.py", true},
		{".hidden/..x.py", true},
		{"bad\xffutf8.py", true}, // a valid name on Linux; escaped on output
		{"1:x.py", true},         // no drive letter
		{"web/C:x.js", true},     // a colon past the first segment is no volume
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := ValidPath(tt.path); got != tt.ok {
				t.Errorf("ValidPath(%q) = %v, want %v", tt.path, got, tt.ok)
			}
			in := Input{Run: completeRun, Findings: []Finding{{ID: "f1", Class: "sqli", Status: StatusProbable, Path: tt.path}}}
			_, err := New(in)
			if tt.ok && err != nil {
				t.Fatalf("New() = %v, want the path accepted", err)
			}
			if !tt.ok && !errors.Is(err, ErrInvalid) {
				t.Fatalf("New() = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestRunIncompleteness(t *testing.T) {
	tests := []struct {
		name       string
		run        state.Summary
		scanStop   bool
		incomplete bool
		reason     string
	}{
		{"complete", completeRun, false, false, ""},
		{"scan stopped", completeRun, true, true, ReasonScanStopped},
		{"no end line", state.Summary{}, false, true, ReasonRunNotEnded},
		{"ended incomplete with reason", state.Summary{Ended: true, Outcome: state.OutcomeIncomplete, Reason: "redact_run_full"}, false, true, "redact_run_full"},
		{"state reason wins over scan", state.Summary{Ended: true, Outcome: state.OutcomeIncomplete, Reason: "budget"}, true, true, "budget"},
		{"malformed reason replaced", state.Summary{Ended: true, Outcome: state.OutcomeIncomplete, Reason: "bad reason\x1b"}, false, true, ReasonRunNotEnded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(Input{Run: tt.run, ScanIncomplete: tt.scanStop})
			if err != nil {
				t.Fatal(err)
			}
			if r.Run.Incomplete != tt.incomplete || r.Run.Reason != tt.reason {
				t.Errorf("Run = %+v, want incomplete %v reason %q", r.Run, tt.incomplete, tt.reason)
			}
		})
	}
}

// An incomplete run must say so in every format and never claim a class is
// covered.
func TestIncompleteMarkedInEveryFormat(t *testing.T) {
	r := newTestReport(t, sampleInput(t, true))
	for _, c := range r.Coverage.Classes {
		if c.Status == ClassCovered {
			t.Errorf("class %s covered in an incomplete run", c.Class)
		}
	}
	want := map[string]string{
		"json":  `"incomplete": true`,
		"sarif": `"executionSuccessful": false`,
		"md":    "INCOMPLETE RUN",
	}
	out := render(t, r)
	for ext, s := range want {
		if !bytes.Contains(out[ext], []byte(s)) {
			t.Errorf("%s output lacks %q", ext, s)
		}
	}
	if !bytes.Contains(out["sarif"], []byte(`"incomplete": true`)) {
		t.Error("SARIF run properties lack incomplete")
	}
	clean := render(t, newTestReport(t, sampleInput(t, false)))
	if bytes.Contains(clean["md"], []byte("INCOMPLETE")) || !bytes.Contains(clean["sarif"], []byte(`"executionSuccessful": true`)) {
		t.Error("complete run reported as incomplete")
	}
}

// #207: Markdown names the frameworks static looked in only when it found
// no route; the names stay out of the JSON contract (run.reason says it).
func TestNoRoutesInMarkdownOnly(t *testing.T) {
	const line = "**No Flask/FastAPI/Express routes found.**"
	in := sampleInput(t, true)
	in.NoRoutesIn = []string{"Flask", "FastAPI", "Express"}
	out := render(t, newTestReport(t, in))
	if !bytes.Contains(out["md"], []byte(line)) {
		t.Errorf("Markdown lacks %q:\n%s", line, out["md"])
	}
	if bytes.Contains(out["json"], []byte("FastAPI")) {
		t.Errorf("JSON carries the framework names:\n%s", out["json"])
	}
	routed := render(t, newTestReport(t, sampleInput(t, true)))
	if bytes.Contains(routed["md"], []byte("routes found")) {
		t.Error("Markdown claims no routes for a run that found some")
	}
}

// Every not-evaluated file appears in every format with its reason, even
// when its name is hostile; exact repeats are listed once.
func TestNotEvaluatedListedEverywhere(t *testing.T) {
	in := sampleInput(t, true)
	in.NotEvaluated = append(in.NotEvaluated, in.NotEvaluated[0])
	r := newTestReport(t, in)
	if got, want := len(r.Coverage.NotEvaluated), len(in.NotEvaluated)-1; got != want {
		t.Fatalf("%d not-evaluated files, want %d", got, want)
	}
	out := render(t, r)
	for _, n := range r.Coverage.NotEvaluated {
		md := "| " + codeSpan(n.Path) + " | " + statusText(string(n.Reason)) + " |"
		if !strings.Contains(string(out["md"]), md) {
			t.Errorf("Markdown lacks row %q", md)
		}
		if !strings.Contains(string(out["sarif"]), `"uri": "`+uriPath(n.Path)+`"`) {
			t.Errorf("SARIF lacks %q", n.Path)
		}
		if !strings.Contains(string(out["sarif"]), "creep/not-evaluated/"+string(n.Reason)) {
			t.Errorf("SARIF lacks reason %s", n.Reason)
		}
	}
}

func TestFindingOrderAndSARIFFilter(t *testing.T) {
	r := newTestReport(t, sampleInput(t, false))
	var ids []string
	for _, f := range r.Findings {
		ids = append(ids, f.ID)
	}
	if got := strings.Join(ids, ","); got != "f1,f2,f5,f3,f4" {
		t.Errorf("order %s, want verified, probable, discarded, not evaluated", got)
	}
	sarif := string(render(t, r)["sarif"])
	for _, id := range []string{"f3", "f4"} {
		if strings.Contains(sarif, `"creep_id": "`+id+`"`) {
			t.Errorf("SARIF result for %s, which is not an alert", id)
		}
	}
}

func TestWilson(t *testing.T) {
	tests := []struct {
		k, n      int
		low, high float64
	}{
		{0, 0, 0, 1},
		{0, 10, 0, 0.278},
		{10, 10, 0.722, 1},
		{9, 10, 0.596, 0.982},
		{1, 1, 0.207, 1},
	}
	for _, tt := range tests {
		low, high := wilson(tt.k, tt.n)
		if low != tt.low || high != tt.high {
			t.Errorf("wilson(%d, %d) = [%v, %v], want [%v, %v]", tt.k, tt.n, low, high, tt.low, tt.high)
		}
	}
}
