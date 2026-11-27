package report

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	readmeListStart = "<!-- not-looked-for:start -->"
	readmeListEnd   = "<!-- not-looked-for:end -->"
)

// readmeNotLookedFor renders the README block from the one list in code.
func readmeNotLookedFor() string {
	var b strings.Builder
	for _, c := range notLookedFor {
		b.WriteString("- " + c.Label + " (`" + c.Class + "`, " + c.CWE + ")\n")
	}
	return b.String()
}

// The README lists exactly the classes the reports list (#365): editing
// one without the other fails here.
func TestReadmeListsNotLookedFor(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	_, rest, ok := strings.Cut(text, readmeListStart+"\n")
	block, _, ok2 := strings.Cut(rest, readmeListEnd)
	if !ok || !ok2 {
		t.Fatalf("README.md has no %s ... %s block", readmeListStart, readmeListEnd)
	}
	if want := readmeNotLookedFor(); block != want {
		t.Errorf("README.md not-looked-for block:\n%s\nwant:\n%s", block, want)
	}
}

var (
	cwePattern = regexp.MustCompile(`^CWE-[1-9][0-9]{0,4}$`)
	// labelPattern keeps labels printable text with no Markdown or SARIF
	// meaning and no ";", which separates them in NotLookedForText.
	labelPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 ,+-]*$`)
)

func TestNotLookedForEntriesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range NotLookedForClasses() {
		if !idPattern.MatchString(c.Class) || seen[c.Class] || !cwePattern.MatchString(c.CWE) || !labelPattern.MatchString(c.Label) {
			t.Errorf("entry %+v: want a unique ID class, a CWE and a plain label", c)
		}
		if ClassCWE(c.Class) != "" {
			t.Errorf("%s is listed as not looked for but has a looked-for CWE", c.Class)
		}
		seen[c.Class] = true
	}
	if !strings.Contains(NotLookedForText(), "memory-safety bugs in C, C++ and unsafe Rust") {
		t.Errorf("text %q does not name memory safety", NotLookedForText())
	}
}

// A report always lists the classes, even an empty run's (#365).
func TestNewAlwaysListsNotLookedFor(t *testing.T) {
	r, err := New(Input{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Coverage.NotLookedFor) != len(notLookedFor) || r.Coverage.NotLookedFor[0].Class != "memory_safety" {
		t.Errorf("coverage.not_looked_for = %+v", r.Coverage.NotLookedFor)
	}
	r.Coverage.NotLookedFor[0].Class = "changed"
	if notLookedFor[0].Class != "memory_safety" {
		t.Error("a report shares the package list")
	}
}
