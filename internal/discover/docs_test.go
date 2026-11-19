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

// extToken is a backticked extension in the README, such as `.py`.
var extToken = regexp.MustCompile("`(\\.[a-z0-9]+)`")

// The README says exactly which extensions discovery reads (#270 review):
// its "Files read" list equals the inventory's ext rows, and no extension
// it lists as not read is in the table, so neither can drift from the
// other.
func TestDocsListInventory(t *testing.T) {
	inv, err := loadInventory()
	if err != nil {
		t.Fatal(err)
	}
	table := slices.Sorted(maps.Keys(inv.exact[matchExt]))
	read, notRead := readmeExtensions(t)
	if !slices.Equal(read, table) {
		t.Errorf("README lists %v as read, inventory.txt has %v", read, table)
	}
	if len(notRead) == 0 {
		t.Error("README lists no extension as not read")
	}
	for _, ext := range notRead {
		if slices.Contains(table, ext) {
			t.Errorf("README says %s is not read, but inventory.txt has it", ext)
		}
	}
}

// The README's list of #! interpreters equals the inventory's shebang
// rows, so an extensionless script is read exactly when the docs say so.
func TestDocsListShebangs(t *testing.T) {
	inv, err := loadInventory()
	if err != nil {
		t.Fatal(err)
	}
	table := slices.Sorted(maps.Keys(inv.exact[matchShebang]))
	line := readmeLine(t, "- **Files read.**")
	_, after, ok := strings.Cut(line, "`#!` line runs ")
	list, _, ok2 := strings.Cut(after, " (directly")
	if !ok || !ok2 {
		t.Fatalf("README \"Files read\" bullet has no interpreter list: %s", line)
	}
	var docs []string
	for _, m := range codeToken.FindAllStringSubmatch(list, -1) {
		docs = append(docs, m[1])
	}
	slices.Sort(docs)
	if !slices.Equal(docs, table) {
		t.Errorf("README lists interpreters %v, inventory.txt has %v", docs, table)
	}
}

var codeToken = regexp.MustCompile("`([^`]+)`")

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

// readmeExtensions returns the sorted extensions of the README's "Files
// read" and "Not read and not listed" bullets.
func readmeExtensions(t *testing.T) (read, notRead []string) {
	t.Helper()
	return extensions(readmeLine(t, "- **Files read.**")), extensions(readmeLine(t, "- **Not read and not listed.**"))
}

func extensions(line string) []string {
	var out []string
	for _, m := range extToken.FindAllStringSubmatch(line, -1) {
		out = append(out, m[1])
	}
	slices.Sort(out)
	return slices.Compact(out)
}
