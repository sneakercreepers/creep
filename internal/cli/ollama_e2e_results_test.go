package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/report"
)

// e2eResults is what TestOllamaEndToEnd writes: counts, enums and creep's
// own output lines, never a model reply.
type e2eResults struct {
	Model    string    `json:"model"`
	Date     string    `json:"date"`
	Init     e2eStep   `json:"init"`
	Doctor   e2eStep   `json:"doctor"`
	Estimate e2eStep   `json:"estimate"`
	Runs     []e2eScan `json:"scans"`
	Why      e2eStep   `json:"why"`
}

type e2eStep struct {
	Command string   `json:"command"`
	Exit    int      `json:"exit"`
	Lines   []string `json:"lines"`
}

// e2eScan is one scan of one twin. Found counts expected findings the run
// reported (verified or probable, same class, file and line); Extra counts
// every other reported finding, so on a safe twin Extra is its false
// positives.
type e2eScan struct {
	App         string  `json:"app"`
	Variant     string  `json:"variant"`
	Pass        string  `json:"pass"`
	Exit        int     `json:"exit"`
	Seconds     float64 `json:"seconds"`
	Calibration string  `json:"calibration"`
	Tier        string  `json:"tier"`
	Reason      string  `json:"reason"`
	Expected    int     `json:"expected"`
	Found       int     `json:"found"`
	Extra       int     `json:"extra"`

	repo, firstID string
}

func (s *e2eScan) score(expected []e2eExpected, rep *report.Report) {
	s.Expected = len(expected)
	want := map[string]bool{}
	for _, e := range expected {
		want[fmt.Sprintf("%s %s:%d", e.Class, e.File, e.Line)] = true
	}
	for _, f := range rep.Findings {
		if f.Status != report.StatusVerified && f.Status != report.StatusProbable {
			continue
		}
		if s.firstID == "" {
			s.firstID = f.ID
		}
		key := fmt.Sprintf("%s %s:%d", f.Class, f.Path, f.Line)
		if want[key] {
			s.Found++
			delete(want, key)
			continue
		}
		s.Extra++
	}
}

// writeE2EResults writes results.json and results.md into dir.
func writeE2EResults(t *testing.T, dir string, res e2eResults) {
	t.Helper()
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	// The directory comes from the workflow's env; os.Root keeps the
	// writes inside it.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("results.json", append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("results.md", []byte(e2eMarkdown(res)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func e2eMarkdown(res e2eResults) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Ollama end to end: `%s` (%s)\n\n", res.Model, res.Date)
	for _, st := range []e2eStep{res.Init, res.Doctor, res.Estimate} {
		fmt.Fprintf(&b, "- `%s`: exit %d\n", st.Command, st.Exit)
		for _, l := range st.Lines {
			fmt.Fprintf(&b, "  - `%s`\n", strings.ReplaceAll(l, "`", "'"))
		}
	}
	b.WriteString("\n| App | Twin | Pass | Exit | Time (s) | Tier | Calibration | Expected found | Other findings | Reason |\n|---|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range res.Runs {
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %.0f | %s | %s | %d/%d | %d | %s |\n", r.App, r.Variant, r.Pass, r.Exit,
			r.Seconds, r.Tier, e2eCell(r.Calibration), r.Found, r.Expected, r.Extra, e2eCell(r.Reason))
	}
	fmt.Fprintf(&b, "\n`%s`: exit %d\n", res.Why.Command, res.Why.Exit)
	return b.String()
}

// e2eCell keeps a value inside one Markdown table cell.
func e2eCell(s string) string {
	return strings.NewReplacer("|", "/", "\n", " ").Replace(s)
}

func TestE2EScore(t *testing.T) {
	expected := []e2eExpected{{"sqli", "app.py", 44}, {"ssrf", "app.py", 61}}
	tests := []struct {
		name         string
		expected     []e2eExpected
		findings     []report.Finding
		found, extra int
		wantFirst    string
	}{
		{"none reported", expected, nil, 0, 0, ""},
		{"exact match", expected, []report.Finding{{ID: "a", Class: "sqli", Path: "app.py", Line: 44, Status: report.StatusProbable}}, 1, 0, "a"},
		{"wrong class is extra", expected, []report.Finding{{ID: "a", Class: "idor", Path: "app.py", Line: 44, Status: report.StatusVerified}}, 0, 1, "a"},
		{"wrong line is extra", expected, []report.Finding{{ID: "a", Class: "sqli", Path: "app.py", Line: 45, Status: report.StatusProbable}}, 0, 1, "a"},
		{"duplicate counts once", expected, []report.Finding{
			{ID: "a", Class: "sqli", Path: "app.py", Line: 44, Status: report.StatusProbable},
			{ID: "b", Class: "sqli", Path: "app.py", Line: 44, Status: report.StatusProbable}}, 1, 1, "a"},
		{"discarded and not evaluated do not count", expected, []report.Finding{
			{ID: "a", Class: "sqli", Path: "app.py", Line: 44, Status: report.StatusDiscarded},
			{ID: "b", Class: "ssrf", Path: "app.py", Line: 61, Status: report.StatusNotEvaluated}}, 0, 0, ""},
		{"safe twin: all false positives", nil, []report.Finding{{ID: "a", Class: "sqli", Path: "app.py", Line: 44, Status: report.StatusProbable}}, 0, 1, "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s e2eScan
			s.score(tt.expected, &report.Report{Findings: tt.findings})
			if s.Found != tt.found || s.Extra != tt.extra || s.firstID != tt.wantFirst || s.Expected != len(tt.expected) {
				t.Errorf("found %d extra %d first %q expected %d, want %d %d %q %d", s.Found, s.Extra, s.firstID, s.Expected, tt.found, tt.extra, tt.wantFirst, len(tt.expected))
			}
		})
	}
}

func TestE2ECellStaysInOneCell(t *testing.T) {
	if got := e2eCell("a|b\nc"); got != "a/b c" {
		t.Errorf("e2eCell = %q", got)
	}
}

func TestLastScanLine(t *testing.T) {
	tests := []struct{ name, stderr, want string }{
		{"none", "stats:\n  calibration: 3 requests\n", ""},
		{"error after notice", "creep scan: discovery sends up to 1 whole source files\ncreep scan: calibration: model unfit\nstats:\n", "creep scan: calibration: model unfit"},
		{"only notice", "creep scan: discovery sends up to 1 whole source files\n", "creep scan: discovery sends up to 1 whole source files"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lastScanLine(tt.stderr); got != tt.want {
				t.Errorf("lastScanLine = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestE2EPathProblems(t *testing.T) {
	ok := func(cmd string) e2eStep { return e2eStep{Command: cmd} }
	calibrated := e2eScan{Exit: 3, Calibration: "89 requests"}
	good := e2eResults{Init: ok("creep init"), Doctor: ok("creep doctor"), Estimate: ok("creep estimate"), Why: ok("creep why"), Runs: []e2eScan{calibrated}}
	with := func(f func(*e2eResults)) e2eResults { r := good; f(&r); return r }
	tests := []struct {
		name string
		res  e2eResults
		want string // substring of the single problem; "" means none
	}{
		{"unfit model is a result", good, ""},
		{"why not run", with(func(r *e2eResults) { r.Why.Exit = e2eNotRun }), ""},
		{"init fails", with(func(r *e2eResults) { r.Init.Exit = 2 }), "creep init: exit 2"},
		{"doctor fails", with(func(r *e2eResults) { r.Doctor.Exit = 3 }), "creep doctor: exit 3"},
		{"estimate fails", with(func(r *e2eResults) { r.Estimate.Exit = 2 }), "creep estimate: exit 2"},
		{"why fails", with(func(r *e2eResults) { r.Why.Exit = 2 }), "creep why: exit 2"},
		{"scan usage error", with(func(r *e2eResults) { r.Runs = []e2eScan{calibrated, {App: "a", Exit: 2}} }), "a  (): exit 2"},
		{"no calibration", with(func(r *e2eResults) { r.Runs = []e2eScan{{Exit: 3}} }), "no calibration cost"},
		{"no scans", with(func(r *e2eResults) { r.Runs = nil }), "no calibration cost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e2ePathProblems(tt.res)
			if tt.want == "" && len(got) != 0 {
				t.Errorf("problems %q, want none", got)
			}
			if tt.want != "" && (len(got) != 1 || !strings.Contains(got[0], tt.want)) {
				t.Errorf("problems %q, want one containing %q", got, tt.want)
			}
		})
	}
}
