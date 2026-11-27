package cli

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/sneakercreepers/creep/internal/gitindex/gitindextest"
)

// TestVendorProofs (#366): a file is vendor only when the repository's own
// ignore patterns cover it and the git index tracks nothing in its tree.
// No directory name counts by itself, a committed file or tree is always
// read, a nested .gitignore applies under its directory, a negation takes
// a file back, a file under an ignored directory stays ignored, and a
// non-ASCII tree proves nothing.
func TestVendorProofs(t *testing.T) {
	repo := t.TempDir()
	writeTreeFile(t, repo, ".gitignore", "deps/\n/out\n*.gen\n!keep.gen\nmixed/\nsub/\n!sub/back.zig\né/\n")
	writeTreeFile(t, repo, "web/.gitignore", "cache/\n")
	writeTreeFile(t, repo, ".git/info/exclude", "local/\n")
	tracked := []string{".gitignore", "web/.gitignore", "app.zig", "mixed/kept.zig", "forced.gen", "vendor/x/y.go"}
	writeTreeFile(t, repo, gitIndexPath, string(gitindextest.Build(gitindextest.Spec{Version: 2, Paths: tracked})))
	tests := []struct {
		file string
		want bool
	}{
		{"deps/lib/a.nim", true},
		{"deps/a/b/c/d.zig", true},
		{"out/bundle.x", true},
		{"src/x.gen", true},
		{"web/cache/m.zig", true},
		{"local/tool.nim", true},
		{"sub/back.zig", true},  // a negation cannot take a file out of an ignored directory
		{"src/keep.gen", false}, // negated
		{"forced.gen", false},   // ignored but committed
		{"mixed/other.zig", false},
		{"cache/m.zig", false}, // web's pattern applies under web only
		{"src/out/a.zig", false},
		{"node_modules/x/index.js", false}, // a well-known name proves nothing
		{"vendor/x/y.go", false},
		{"vendor/x/z.go", false},
		{"app.zig", false},
		{"new.zig", false}, // untracked, not ignored: the author's own work
		{"é/x.zig", false},
	}
	for _, tt := range tests {
		writeTreeFile(t, repo, tt.file, "x\n")
	}
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
// directory, or one creep cannot read whole, nothing is vendor, so an
// ignored tree is read like first-party code.
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
			writeTreeFile(t, repo, ".gitignore", "deps/\n")
			writeTreeFile(t, repo, "deps/ok/index.js", "x\n")
			tt.index(t, repo)
			if openProofs(t, repo).proven("deps/ok/index.js") {
				t.Error("a tree is proven vendor without a readable git index")
			}
		})
	}
}

// TestVendorProofsIgnoreFileBounds: an ignore file creep cannot read whole
// (over the cap, or a directory) ignores nothing, so its tree is read.
func TestVendorProofsIgnoreFileBounds(t *testing.T) {
	tests := []struct {
		name   string
		ignore func(t *testing.T, repo string)
	}{
		{"oversized", func(t *testing.T, repo string) {
			big := make([]byte, maxGitIgnoreBytes+1)
			copy(big, "deps/\n")
			for i := len("deps/\n"); i < len(big); i++ {
				big[i] = '#'
			}
			writeTreeFile(t, repo, ".gitignore", string(big))
		}},
		{"a directory", func(t *testing.T, repo string) { mkdirTree(t, repo, ".gitignore") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := t.TempDir()
			tt.ignore(t, repo)
			writeTreeFile(t, repo, "deps/ok/index.js", "x\n")
			writeTreeFile(t, repo, gitIndexPath, string(gitindextest.Build(gitindextest.Spec{Version: 2, Paths: []string{"app.py"}})))
			if openProofs(t, repo).proven("deps/ok/index.js") {
				t.Error("an unreadable ignore file proved a tree vendor")
			}
		})
	}
}

// ecosystemNames are package managers, their directories and marks, and
// languages: no vendor or generated rule may name one (#366).
var ecosystemNames = regexp.MustCompile(`(?i)\b(node_modules|bower_components|jspm_packages|site-packages|dist-packages|__pypackages__|venv|pyvenv|third_party|npm|yarn|pnpm|pip|pipenv|poetry|composer|bundler|gem|gems|cargo|maven|gradle|nuget|cocoapods|pods|golang|python|javascript|typescript|php|ruby|java|kotlin|scala|rust|elixir|erlang|swift|dart|perl|csharp|protoc|protobuf|protocol buffer|package\.json|go\.mod|modules\.txt)\b`)

// TestRulesNameNoEcosystem (#366): the vendor and generated rules name no
// package manager, dependency directory or language, in code or comments,
// so creep needs no per-ecosystem data to tell vendor or generated code.
func TestRulesNameNoEcosystem(t *testing.T) {
	files := []string{
		"vendorproof.go", "trackedtree.go",
		filepath.Join("..", "repofile", "ignore.go"), filepath.Join("..", "repofile", "gitignore.go"),
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if m := ecosystemNames.Find(data); m != nil {
			t.Errorf("%s names %q", name, m)
		}
	}
}

// TestEcosystemDenyListCatches: the deny list is not vacuous; the old
// rules' names are on it.
func TestEcosystemDenyListCatches(t *testing.T) {
	for _, s := range []string{`case "node_modules":`, `"venv", ".venv"`, "pyvenv.cfg", "JavaScript or TypeScript", "protoc's header", "package.json"} {
		if !ecosystemNames.MatchString(s) {
			t.Errorf("deny list misses %q", s)
		}
	}
}

func openProofs(t *testing.T, repo string) *vendorProofs {
	t.Helper()
	root, err := os.OpenRoot(repo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return newVendorProofs(context.Background(), root)
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
