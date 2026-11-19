package report

import (
	"bytes"
	"strings"
	"testing"
)

// TestByDesignSummary: the count names only by-design reasons, in a fixed
// order, never a path, and is empty when every listed file is a gap (#213).
func TestByDesignSummary(t *testing.T) {
	hostile := hostilePaths[0]
	tests := []struct {
		name  string
		files []NotEvaluated
		want  string
	}{
		{"none listed", nil, ""},
		{"only gaps", []NotEvaluated{{Path: "a.py", Reason: SkipSyntaxError}, {Path: "b.go", Reason: SkipUnsupported}}, ""},
		{"one vendor file", []NotEvaluated{{Path: "node_modules/a/i.js", Reason: SkipVendor}}, "1 file left out by design (vendor 1)"},
		{"fixed order whatever the listing", []NotEvaluated{
			{Path: "m.js", Reason: SkipMinified}, {Path: "g.py", Reason: SkipGenerated},
			{Path: "x.py", Reason: SkipTooLarge}, {Path: "venv/v.py", Reason: SkipVendor}, {Path: "n.js", Reason: SkipMinified},
		}, "4 files left out by design (vendor 1, generated 1, minified 2)"},
		{"hostile path is not printed", []NotEvaluated{{Path: hostile, Reason: SkipGenerated}}, "1 file left out by design (generated 1)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ByDesignSummary(tt.files); got != tt.want {
				t.Errorf("ByDesignSummary = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestByDesignReasons: exactly vendor, generated and minified are by
// design; every other closed reason is a gap that makes a run incomplete.
func TestByDesignReasons(t *testing.T) {
	for r := range skipReasons {
		want := r == SkipVendor || r == SkipGenerated || r == SkipMinified
		if r.ByDesign() != want {
			t.Errorf("%s.ByDesign() = %v, want %v", r, r.ByDesign(), want)
		}
	}
	if SkipReason("unknown").ByDesign() {
		t.Error("an unknown reason reads as by design")
	}
}

// TestByDesignInEveryFormat: Markdown and SARIF state the by-design count
// next to the coverage, and say nothing when no file was left out by design.
func TestByDesignInEveryFormat(t *testing.T) {
	const want = "no class covers the 3 files left out by design (vendor 2, generated 1)"
	with := render(t, newTestReport(t, sampleInput(t, false)))
	for _, ext := range []string{"md", "sarif"} {
		if !strings.Contains(strings.ToLower(string(with[ext])), want) {
			t.Errorf("%s lacks %q:\n%s", ext, want, with[ext])
		}
	}
	in := sampleInput(t, false)
	in.NotEvaluated = in.NotEvaluated[:1]
	without := render(t, newTestReport(t, in))
	for ext, out := range without {
		if bytes.Contains(out, []byte("left out by design")) {
			t.Errorf("%s names a by-design count with none left out:\n%s", ext, out)
		}
	}
}
