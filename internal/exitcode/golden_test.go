package exitcode

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/exit_codes.golden")

var goldenPath = filepath.Join("testdata", "exit_codes.golden")

// TestExitCodesGolden pins every code's value and meaning (#135): CI
// pipelines branch on them, so a change must show up as a golden diff. The
// broken cases prove that a changed value, meaning, or a dropped or added
// code each fails the comparison; they derive from the table so a deliberate
// change accepted with -update cannot make one coincide with the golden.
func TestExitCodesGolden(t *testing.T) {
	tests := []struct {
		name    string
		entries func() []entry
		match   bool
	}{
		{"current table", func() []entry { return table }, true},
		{"broken: value changed", func() []entry { return withEntry(1, entry{table[1].code + 10, table[1].meaning}) }, false},
		{"broken: meaning changed", func() []entry { return withEntry(1, entry{table[1].code, table[1].meaning + " changed"}) }, false},
		{"broken: code dropped", func() []entry { return table[:len(table)-1] }, false},
		{"broken: code added", func() []entry { return append(slices.Clone(table), entry{len(table) + 10, "new"}) }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := render(tt.entries())
			if tt.match && *update {
				writeGolden(t, got)
			}
			diff := goldenDiff(t, got)
			if tt.match && diff != "" {
				t.Errorf("exit codes differ from %s (rerun with -update to accept):\n%s", goldenPath, diff)
			}
			if !tt.match && diff == "" {
				t.Error("the golden comparison missed a changed table")
			}
		})
	}
}

func withEntry(i int, e entry) []entry {
	entries := slices.Clone(table)
	entries[i] = e
	return entries
}

func writeGolden(t *testing.T, got string) {
	t.Helper()
	if err := os.WriteFile(goldenPath, []byte(got), 0o600); err != nil {
		t.Fatal(err)
	}
}

// goldenDiff returns the lines that differ from the golden, or "".
func goldenDiff(t *testing.T, got string) string {
	t.Helper()
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	return lineDiff(strings.ReplaceAll(string(want), "\r\n", "\n"), got)
}

// lineDiff returns a unified-style line diff of want and got, or "" when
// they are equal. Lines are matched by longest common subsequence. A copy
// lives in internal/cli: a shared test helper package would need its own
// layer row for 30 lines.
func lineDiff(want, got string) string {
	if want == got {
		return ""
	}
	a, b := strings.Split(want, "\n"), strings.Split(got, "\n")
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out strings.Builder
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			i, j = i+1, j+1
		case i < len(a) && (j == len(b) || lcs[i+1][j] >= lcs[i][j+1]):
			fmt.Fprintf(&out, "-%s\n", a[i])
			i++
		default:
			fmt.Fprintf(&out, "+%s\n", b[j])
			j++
		}
	}
	return out.String()
}
