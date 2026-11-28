package cli

import (
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

// #366: creep estimate measures the same read as a scan. A file in a
// language no inventory row names counts as a whole file sent and adds its
// bytes to the input tokens; a file named as a text format adds nothing.
func TestEstimateCountsAnyTextFile(t *testing.T) {
	zig := strings.Repeat("pub fn handler() void { run(\"x\"); }\n", 100)
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"python only", map[string]string{"app.py": "@flask"}, "1 calls send 1 whole source files"},
		{"plus a zig file", map[string]string{"app.py": "@flask", "src/main.zig": zig}, "1 calls send 2 whole source files"},
		{"plus prose", map[string]string{"app.py": "@flask", "NOTES.md": zig}, "1 calls send 1 whole source files"},
	}
	tokens := map[string]int{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, tt.files, "")
			code, out, errOut := runScanWith(offlineDeps(t, true), "estimate", "--config", cfg)
			if code != exitcode.OK || !strings.Contains(out, tt.want) {
				t.Fatalf("exit %d, want 0 and %q\n%s\n%s", code, tt.want, out, errOut)
			}
			_, in, _ := estimateRow(t, out, "M *")
			tokens[tt.name] = in
		})
	}
	if tokens["plus a zig file"] <= tokens["python only"] {
		t.Errorf("input tokens %d with a zig file, %d without: the wider read is not measured", tokens["plus a zig file"], tokens["python only"])
	}
	if tokens["plus prose"] != tokens["python only"] {
		t.Errorf("input tokens %d with prose, %d without: a text format is counted", tokens["plus prose"], tokens["python only"])
	}
}
