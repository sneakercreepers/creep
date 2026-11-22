package report

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewChecksIncremental: the scope holds counts that add up, and a full
// scan carries none.
func TestNewChecksIncremental(t *testing.T) {
	tests := []struct {
		name string
		inc  Incremental
		ok   bool
	}{
		{"full scan", Incremental{}, true},
		{"empty list", Incremental{On: true}, true},
		{"some listed paths missing", Incremental{On: true, Listed: 3, Missing: 1}, true},
		{"every listed path missing", Incremental{On: true, Listed: 2, Missing: 2}, true},
		{"more missing than listed", Incremental{On: true, Listed: 1, Missing: 2}, false},
		{"negative listed", Incremental{On: true, Listed: -1}, false},
		{"negative missing", Incremental{On: true, Listed: 1, Missing: -1}, false},
		{"counts on a full scan", Incremental{Listed: 2}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Input{Incremental: tt.inc})
			if (err == nil) != tt.ok || (err != nil && !errors.Is(err, ErrInvalid)) {
				t.Fatalf("New(%+v) = %v, want ok %v", tt.inc, err, tt.ok)
			}
		})
	}
}

// incrementalInput is a complete incremental run: one changed file
// scanned, one listed path that is no file, two unchanged files (one with
// a hostile name) and a vendor file.
func incrementalInput(t *testing.T) Input {
	in := sampleInput(t, false)
	in.NotEvaluated = []NotEvaluated{
		{Path: "node_modules/pkg/index.js", Reason: SkipVendor},
		{Path: "app/old.py", Reason: SkipUnchanged},
		{Path: hostilePaths[1], Reason: SkipUnchanged},
	}
	in.Incremental = Incremental{On: true, Listed: 2, Missing: 1}
	return in
}

// TestIncrementalInEveryFormat (#26): Markdown and SARIF mark the run
// incremental with its counts, never a path; JSON lists every unchanged
// file and gains no other field, and still validates against the v1
// schema; a full scan says nothing about it.
func TestIncrementalInEveryFormat(t *testing.T) {
	const mark = "incremental scan (--changed): 1 listed file scanned, 1 listed path is no file creep reads"
	out := render(t, newTestReport(t, incrementalInput(t)))
	for _, ext := range []string{"md", "sarif"} {
		if !strings.Contains(string(out[ext]), mark) || !strings.Contains(string(out[ext]), "2 unchanged files not evaluated (reason unchanged)") {
			t.Errorf("%s lacks the incremental mark:\n%s", ext, out[ext])
		}
	}
	if !strings.Contains(string(out["md"]), "**Incremental scan.**") || !strings.Contains(string(out["sarif"]), `"creep/incremental"`) {
		t.Errorf("Markdown banner or SARIF note missing:\n%s\n%s", out["md"], out["sarif"])
	}
	if !strings.Contains(string(out["md"]), "No class covers the 3 files left out by design (vendor 1, unchanged 2)") {
		t.Errorf("Markdown lacks the by-design count beside the coverage:\n%s", out["md"])
	}
	if got := bytes.Count(out["json"], []byte(`"reason": "unchanged"`)); got != 2 {
		t.Errorf("JSON lists %d unchanged files, want 2:\n%s", got, out["json"])
	}
	if bytes.Contains(out["json"], []byte("incremental")) {
		t.Errorf("JSON gained an incremental field; v1 only gains the unchanged reason:\n%s", out["json"])
	}
	assertValid(t, loadJSON(t, filepath.Join("..", "..", "docs", "schemas", "report-v1.json")), out["json"])
	full := render(t, newTestReport(t, sampleInput(t, false)))
	for ext, data := range full {
		if bytes.Contains(bytes.ToLower(data), []byte("incremental")) {
			t.Errorf("full scan %s mentions an incremental scan:\n%s", ext, data)
		}
	}
}

// TestReadJSONKeepsUnchanged: `creep why` reads an incremental report back
// with its unchanged files.
func TestReadJSONKeepsUnchanged(t *testing.T) {
	out := render(t, newTestReport(t, incrementalInput(t)))
	rep, err := ReadJSON(bytes.NewReader(out["json"]))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range rep.Coverage.NotEvaluated {
		if f.Reason == SkipUnchanged {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("read back %d unchanged files, want 2", n)
	}
}
