package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/report"
)

// Regression (#209 I3): the incomplete mark counts the gaps apart from the
// files and sinks left out by design, so "not evaluated" never includes
// what does not make a run incomplete.
func TestIncompleteMarkSeparatesByDesign(t *testing.T) {
	file := func(reason report.SkipReason) report.NotEvaluated {
		return report.NotEvaluated{Path: "a.py", Reason: reason}
	}
	notEvaluated := func(reason string) report.Finding {
		return report.Finding{ID: "sink-1", Status: report.StatusNotEvaluated, Reason: reason}
	}
	tests := []struct {
		name     string
		files    []report.NotEvaluated
		findings []report.Finding
		want     string
	}{
		{"nothing listed", nil, nil, "0 not evaluated or partial, 0 left out by design"},
		{"by-design files only", []report.NotEvaluated{file(report.SkipVendor), file(report.SkipGenerated), file(report.SkipMinified)}, nil,
			"0 not evaluated or partial, 3 left out by design"},
		{"file gap beside vendor", []report.NotEvaluated{file(report.SkipVendor), file(report.SkipTooLarge)}, nil,
			"1 not evaluated or partial, 1 left out by design"},
		{"low-risk skip is by design", nil, []report.Finding{notEvaluated(reasonLowRisk), notEvaluated("budget")},
			"1 not evaluated or partial, 1 left out by design"},
		{"no reason is a gap", nil, []report.Finding{notEvaluated("")}, "1 not evaluated or partial, 0 left out by design"},
		{"partial verdict is a gap", nil, []report.Finding{{ID: "sink-2", Status: report.StatusDiscarded, Partial: true}, {ID: "sink-3", Status: report.StatusProbable}},
			"1 not evaluated or partial, 0 left out by design"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := &report.Report{Findings: tt.findings}
			rep.Run.Reason = "budget"
			rep.Coverage.NotEvaluated = tt.files
			if got := incompleteMark(rep); !strings.Contains(got, "(reason budget): "+tt.want+";") {
				t.Fatalf("mark %q, want %q", got, tt.want)
			}
		})
	}
}

// Regression (#209 I3): a probable or verified finding from a partial
// slice is flagged in the text summary; other statuses are not listed.
func TestPrintFindingsFlagsPartial(t *testing.T) {
	tests := []struct {
		name string
		f    report.Finding
		want string // the listed line, or "" for none
	}{
		{"probable partial", report.Finding{ID: "sink-4", Status: report.StatusProbable, Class: "sqli", Path: "big.py", Line: 609, Partial: true},
			"  sink-4  probable  sqli  big.py:609  partial slice\n"},
		{"verified partial", report.Finding{ID: "sink-5", Status: report.StatusVerified, Class: "ssrf", Path: "a.py", Line: 2, Partial: true},
			"  sink-5  verified  ssrf  a.py:2  partial slice\n"},
		{"probable whole", report.Finding{ID: "sink-1", Status: report.StatusProbable, Class: "sqli", Path: "a.py", Line: 3},
			"  sink-1  probable  sqli  a.py:3\n"},
		{"discarded partial not listed", report.Finding{ID: "sink-2", Status: report.StatusDiscarded, Class: "sqli", Path: "a.py", Line: 3, Partial: true}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			printFindings(&b, []report.Finding{tt.f})
			_, listed, _ := strings.Cut(b.String(), "not evaluated\n")
			if listed != tt.want {
				t.Fatalf("listed %q, want %q", listed, tt.want)
			}
		})
	}
}

// Through the CLI: a vulnerable verdict from a cut slice is flagged, and
// the mark counts the vendor file apart from the gaps (the verdict and the
// file the slicer could not read whole).
func TestScanSummaryFlagsPartialVerdict(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": longHandler(), "README.md": "# x\n"}, "")
	m := &fakeModel{verdict: map[string]string{"sql_injection": "vulnerable"}}
	code, out, errOut := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--config", cfg)
	if code != exitcode.Incomplete {
		t.Fatalf("exit %d, want 4\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	assertContains(t, "stdout", out, []string{"probable  sqli  app.py:", "  partial slice\n",
		"INCOMPLETE RUN (reason partial_slice): 2 not evaluated or partial, 1 left out by design;"})
}

// The text summary opens with the calibration header and ends with the
// incomplete mark, then the report files written, if any; the model name
// never reaches the terminal as raw control characters.
func TestPrintScanTextOrder(t *testing.T) {
	cal := calibrate.Calibration{Result: calibrate.Result{Tier: calibrate.TierM, Fitness: calibrate.Fitness{Fit: true}}, Model: models.Identity{Model: "m\x1b[2J"}}
	tests := []struct {
		name    string
		written []string
		last    string
	}{
		{"reports written", []string{".creep/report.json", ".creep/report.sarif"}, "reports: .creep/report.json .creep/report.sarif"},
		{"no report", nil, "INCOMPLETE RUN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := &report.Report{Run: report.RunInfo{Incomplete: true, Reason: "planner_rejected"}}
			var out bytes.Buffer
			printScanText(&out, cal, rep, tt.written)
			lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
			if !strings.HasPrefix(lines[0], `calibration: model "m`) || !strings.Contains(lines[0], "tier M") {
				t.Errorf("first line %q, want the calibration header", lines[0])
			}
			if strings.ContainsRune(out.String(), 0x1b) {
				t.Errorf("raw escape in the summary:\n%q", out.String())
			}
			if last := lines[len(lines)-1]; !strings.Contains(last, tt.last) {
				t.Errorf("last line %q, want %q", last, tt.last)
			}
		})
	}
}
