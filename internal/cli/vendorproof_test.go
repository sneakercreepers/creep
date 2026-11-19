package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sneakercreepers/creep/internal/gitindex/gitindextest"
)

// TestVendorProofs (#213): a tree is installed only when its mark is a
// regular file spelled byte for byte (PACKAGE.JSON or PyVenv.CFG prove
// nothing, even where a stat of package.json would find them) and the git
// index tracks nothing in it. A committed mark, a committed file in a real
// tree, a submodule, a non-ASCII tree and a missing or unreadable index
// prove nothing; Go and PHP marks never do.
func TestVendorProofs(t *testing.T) {
	marks := []string{
		"node_modules/upper/PACKAGE.JSON", "node_modules/ok/package.json",
		"node_modules/@s/ok/package.json", "venv/PyVenv.CFG", ".venv/pyvenv.cfg",
		"node_modules/forged/package.json", "node_modules/mixed/package.json",
		"web/node_modules/sub/package.json", "node_modules/é/package.json",
		"vendor/modules.txt", "composer.json",
	}
	tracked := []string{
		"app.py", "node_modules/forged/package.json", "node_modules/forged/app.js",
		"node_modules/mixed/extra.js", "web",
	}
	tests := []struct {
		file string
		want bool
	}{
		{"node_modules/ok/index.js", true},
		{"node_modules/ok/src/addon.cc", true},
		{"node_modules/@s/ok/lib/i.ts", true},
		{".venv/lib/x.py", true},
		{".venv/lib/m/_speedups.c", true},
		{"node_modules/upper/index.js", false},
		{"venv/lib/x.py", false},
		{"node_modules/dir/index.js", false}, // the mark is a directory
		{"node_modules/missing/index.js", false},
		{"node_modules/forged/app.js", false},
		{"node_modules/forged/other.js", false},
		{"node_modules/mixed/index.js", false}, // a committed file in the tree
		{"web/node_modules/sub/index.js", false},
		{"node_modules/é/index.js", false},
		{"vendor/x/y.go", false},
		{"vendor/acme/a.php", false},
		{"app.py", false},
	}
	repo := t.TempDir()
	for _, name := range marks {
		writeTreeFile(t, repo, name, "{}")
	}
	if err := os.MkdirAll(filepath.Join(repo, "node_modules", "dir", "package.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTreeFile(t, repo, gitIndexPath, string(gitindextest.Build(gitindextest.Spec{Version: 2, Paths: tracked})))
	proofs := openProofs(t, repo)
	for _, tt := range tests {
		for range 2 { // the second answer comes from the cache
			if got := proofs.proven(tt.file); got != tt.want {
				t.Errorf("proven(%q) = %v, want %v", tt.file, got, tt.want)
			}
		}
	}
}

// TestVendorProofsNeedAGitIndex: with no index, an index that is a
// directory, or one creep cannot read whole, no tree is installed, so its
// files are read like first-party code.
func TestVendorProofsNeedAGitIndex(t *testing.T) {
	tests := []struct {
		name  string
		index func(t *testing.T, repo string)
	}{
		{"no .git", func(*testing.T, string) {}},
		{"no index", func(t *testing.T, repo string) { mkdirTree(t, repo, ".git") }},
		{"index is a directory", func(t *testing.T, repo string) { mkdirTree(t, repo, gitIndexPath) }},
		{"bad checksum", func(t *testing.T, repo string) {
			data := gitindextest.Build(gitindextest.Spec{Version: 2, Paths: []string{"app.py"}})
			data[len(data)-1] ^= 1
			writeTreeFile(t, repo, gitIndexPath, string(data))
		}},
		{"split index", func(t *testing.T, repo string) {
			writeTreeFile(t, repo, gitIndexPath, string(gitindextest.Build(gitindextest.Spec{Version: 2, Ext: gitindextest.Extension("link", make([]byte, 20))})))
		}},
		{"unsigned", func(t *testing.T, repo string) {
			writeTreeFile(t, repo, gitIndexPath, string(gitindextest.Build(gitindextest.Spec{Version: 2, NoSign: true})))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := t.TempDir()
			writeTreeFile(t, repo, "node_modules/ok/package.json", "{}")
			tt.index(t, repo)
			if openProofs(t, repo).proven("node_modules/ok/index.js") {
				t.Error("a tree is proven installed without a readable git index")
			}
		})
	}
}

// TestVendorProofsLinkedMark: a mark that is a link proves nothing, even
// when it points at a regular file inside the repository.
func TestVendorProofsLinkedMark(t *testing.T) {
	repo := t.TempDir()
	writeTreeFile(t, repo, "real.json", "{}")
	mkdirTree(t, repo, "node_modules/linked")
	if err := os.Symlink(filepath.Join(repo, "real.json"), filepath.Join(repo, "node_modules", "linked", "package.json")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks need privileges here: %v", err)
		}
		t.Fatal(err)
	}
	writeTreeFile(t, repo, gitIndexPath, string(gitindextest.Build(gitindextest.Spec{Version: 2, Paths: []string{"real.json"}})))
	if openProofs(t, repo).proven("node_modules/linked/index.js") {
		t.Error("a linked mark proves a tree installed")
	}
}

func openProofs(t *testing.T, repo string) *vendorProofs {
	t.Helper()
	root, err := os.OpenRoot(repo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return newVendorProofs(root)
}

func mkdirTree(t *testing.T, repo, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(repo, filepath.FromSlash(name)), 0o700); err != nil {
		t.Fatal(err)
	}
}

func writeTreeFile(t *testing.T, repo, name, content string) {
	t.Helper()
	path := filepath.Join(repo, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
