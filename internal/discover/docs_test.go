package discover

import (
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// codeToken is a backticked token in the README, such as `.png`.
var codeToken = regexp.MustCompile("`([^`]+)`")

// The README says exactly which files discovery does not read (#366): the
// backticked extensions, names and patterns of its "Not read" bullet equal
// the rows of formats.txt, so neither can drift from the other.
func TestDocsListFormats(t *testing.T) {
	formats, err := loadFormats()
	if err != nil {
		t.Fatal(err)
	}
	table := slices.Collect(maps.Keys(formats.exts))
	table = append(table, slices.Collect(maps.Keys(formats.names))...)
	for _, g := range formats.globs {
		table = append(table, g.prefix+"*"+g.suffix)
	}
	slices.Sort(table)
	var docs []string
	for _, m := range codeToken.FindAllStringSubmatch(readmeLine(t, "- **Not read.**"), -1) {
		if m[1] != "not_code" && m[1] != "binary" && !strings.HasPrefix(m[1], "internal/") && !strings.HasPrefix(m[1], "Test") {
			docs = append(docs, m[1])
		}
	}
	slices.Sort(docs)
	if !slices.Equal(docs, table) {
		t.Errorf("README lists %v as not read, formats.txt has %v", docs, table)
	}
}

// readmeLine returns the README line that starts with prefix.
func readmeLine(t *testing.T, prefix string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("README has no line starting %q", prefix)
	return ""
}
