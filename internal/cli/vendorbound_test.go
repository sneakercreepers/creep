package cli

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/sneakercreepers/creep/internal/gitindex/gitindextest"
	"github.com/sneakercreepers/creep/internal/report"
)

// TestVendorCannotHideTheRepository (#376 auditor M2): an archive can carry
// its own .git/index and ignore file. A catch-all pattern at the root
// proves nothing, and vendor that would leave discovery no file it opens
// is dropped, so the code is read like first-party code, never listed
// vendor behind exit 0. An ordinary ignored install stays vendor.
func TestVendorCannotHideTheRepository(t *testing.T) {
	tests := []struct {
		name    string
		ignore  string
		exclude string
		tracked []string
		vendor  bool // src/app.zig is listed vendor
	}{
		{"star", "*\n", "", []string{".gitignore"}, false},
		{"rooted star", "/*\n!/.gitignore\n", "", []string{".gitignore"}, false},
		{"double star", "**\n", "", []string{".gitignore"}, false},
		{"star in exclude", "", "*\n", nil, false},
		{"every code tree named", "src/\ndeps/\n", "", []string{".gitignore", "README.md"}, false},
		{"an install beside first-party code", "deps/\n", "", []string{".gitignore", "README.md", "main.zig"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := t.TempDir()
			files := map[string]string{"README.md": "# x\n", "src/app.zig": "pub fn main() void {}\n", "deps/lib/x.zig": "x\n"}
			if tt.vendor {
				files["main.zig"] = "pub fn main() void {}\n"
			}
			if tt.ignore != "" {
				files[".gitignore"] = tt.ignore
			}
			if tt.exclude != "" {
				files[gitExcludePath] = tt.exclude
			}
			for name, content := range files {
				writeTreeFile(t, repo, name, content)
			}
			writeTreeFile(t, repo, gitIndexPath, string(gitindextest.Build(gitindextest.Spec{Version: 2, Paths: tt.tracked})))
			got := walkTree(t, repo)
			if tt.vendor {
				if !slices.Contains(got.gaps, report.NotEvaluated{Path: "deps/lib/x.zig", Reason: report.SkipVendor}) {
					t.Errorf("gaps %+v: the install must stay vendor", got.gaps)
				}
				return
			}
			if hasVendor(got.gaps) || !slices.Contains(got.paths, "src/app.zig") || !slices.Contains(got.paths, "deps/lib/x.zig") {
				t.Errorf("paths %v gaps %+v: want every file read and none vendor", got.paths, got.gaps)
			}
		})
	}
}

func walkTree(t *testing.T, repo string) repoFiles {
	t.Helper()
	root, err := os.OpenRoot(repo)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := walkRepo(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
