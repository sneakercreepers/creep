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

// readmeExtensions returns the sorted extensions of the README's "Files
// read" and "Not read and not listed" bullets.
func readmeExtensions(t *testing.T) (read, notRead []string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "- **Files read.**"):
			read = extensions(line)
		case strings.HasPrefix(line, "- **Not read and not listed.**"):
			notRead = extensions(line)
		}
	}
	if read == nil {
		t.Fatal("README has no \"- **Files read.**\" bullet")
	}
	return read, notRead
}

func extensions(line string) []string {
	var out []string
	for _, m := range extToken.FindAllStringSubmatch(line, -1) {
		out = append(out, m[1])
	}
	slices.Sort(out)
	return slices.Compact(out)
}
