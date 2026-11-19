package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestTrackedPathsTouches: the name guard counts a tree as tracked when git
// holds anything in it, the tree itself, or a path above it (a submodule).
// Names are folded the way NTFS and case-insensitive systems resolve them
// (case, trailing dots and spaces), and a sibling with the same prefix does
// not count.
func TestTrackedPathsTouches(t *testing.T) {
	tracked := newTrackedPaths([]string{
		"src/app.py", "node_modules/evil/app.js", "Web", "Node_Modules/Up/x.js", "node_modules/gitlink",
		"node_modules/evil-two.js", "node_modules./dot/app.js", "node_modules/space /app.js", "node_modules/Koa/app.js",
	})
	tests := []struct {
		dir  string
		want bool
	}{
		{"node_modules/evil", true},
		{"node_modules/up", true},
		{"NODE_MODULES/EVIL", true},
		{"web/node_modules/x", true},
		{"node_modules/gitlink", true},
		{"src", true},
		{"node_modules/dot", true},   // node_modules./dot on NTFS
		{"node_modules/space", true}, // a trailing space on NTFS
		{"node_modules/koa", true},   // the Kelvin sign lowercases to k
		{"node_modules/ev", false},
		{"node_modules/evil-two", false},
		{"node_modules/express", false},
		{"venv", false},
		{".venv", false},
	}
	for _, tt := range tests {
		if got := tracked.touches(tt.dir); got != tt.want {
			t.Errorf("touches(%q) = %v, want %v", tt.dir, got, tt.want)
		}
	}
	if (trackedPaths{}).touches("node_modules/x") {
		t.Error("an empty index tracks a tree")
	}
}

// TestTrackedIndexComparesIdentity (#267 tester H1): a tracked name that
// the file system resolves into the tree tracks it, whatever its spelling.
// A link stands in for an alias here (an 8.3 name, another case or Unicode
// form): names differ, identity does not. A tracked name that cannot be
// resolved for any reason but its absence counts as tracked; an absent one
// holds no file and does not.
func TestTrackedIndexComparesIdentity(t *testing.T) {
	repo := t.TempDir()
	mkdirTree(t, repo, "node_modules/evil")
	mkdirTree(t, repo, "node_modules/ok")
	mkdirTree(t, repo, "other/evil")
	outside := t.TempDir()
	links := map[string]string{
		"alias":  "node_modules", // relative: os.Root refuses absolute link targets
		"escape": outside,
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(repo, name)); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlinks need privileges here: %v", err)
			}
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(repo)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// The alias must resolve, or the rows below would pass by failing closed.
	if _, err := root.Lstat("alias/evil"); err != nil {
		t.Fatalf("alias does not resolve inside the root: %v", err)
	}
	tests := []struct {
		name    string
		tracked []string
		dir     string
		want    bool
	}{
		{"alias resolves into the tree", []string{"alias/evil/app.js"}, "node_modules/evil", true},
		{"alias resolves elsewhere", []string{"alias/evil/app.js"}, "node_modules/ok", false},
		{"alias of a parent is a gitlink", []string{"alias"}, "node_modules/ok", false},
		{"unresolvable name", []string{"escape/x/app.js"}, "node_modules/ok", true},
		{"absent name", []string{"gone/x/app.js", "node_modules/gone/app.js"}, "node_modules/ok", false},
		{"tree itself missing", nil, "node_modules/missing", true},
		{"same name under another parent", []string{"other/evil/app.js"}, "node_modules/evil", false},
		{"deeper path through the alias", []string{"alias/evil/deep/app.js"}, "node_modules/evil", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newTrackedIndex(tt.tracked).tracks(root, tt.dir); got != tt.want {
				t.Errorf("tracks(%q) with %q = %v, want %v", tt.dir, tt.tracked, got, tt.want)
			}
		})
	}
}

// TestTrackedIndexCapsSiblings: past maxTrackedSiblings tracked names
// beside a tree's aliases, or beside a directory above it, the tree counts
// as tracked, so the identity check stays bounded and fails closed.
func TestTrackedIndexCapsSiblings(t *testing.T) {
	repo := t.TempDir()
	mkdirTree(t, repo, "node_modules/ok")
	root, err := os.OpenRoot(repo)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	many := func(prefix string, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("%sf%d.js", prefix, i)
		}
		return out
	}
	tests := []struct {
		name    string
		tracked []string
		want    bool
	}{
		{"at the cap beside the tree", many("node_modules/", maxTrackedSiblings), false},
		{"past the cap beside the tree", many("node_modules/", maxTrackedSiblings+1), true},
		{"past the cap beside node_modules", many("", maxTrackedSiblings+1), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newTrackedIndex(tt.tracked).tracks(root, "node_modules/ok"); got != tt.want {
				t.Errorf("tracks = %v, want %v", got, tt.want)
			}
		})
	}
}

// BenchmarkTrackedIndexTracks: a repository with 20,000 tracked
// directories (20 top-level directories of 1,000 each, on disk) and 300
// installed packages. Each iteration builds the index and checks every
// package, as one scan does.
func BenchmarkTrackedIndexTracks(b *testing.B) {
	repo := b.TempDir()
	var tracked []string
	for i := range 20 {
		for j := range 1000 {
			dir := fmt.Sprintf("src%d/d%d", i, j)
			if err := os.MkdirAll(filepath.Join(repo, filepath.FromSlash(dir)), 0o700); err != nil {
				b.Fatal(err)
			}
			tracked = append(tracked, dir+"/x.go")
		}
	}
	trees := make([]string, 300)
	for i := range trees {
		trees[i] = fmt.Sprintf("node_modules/p%d", i)
		if err := os.MkdirAll(filepath.Join(repo, filepath.FromSlash(trees[i])), 0o700); err != nil {
			b.Fatal(err)
		}
	}
	root, err := os.OpenRoot(repo)
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	for b.Loop() {
		index := newTrackedIndex(tracked)
		for _, tree := range trees {
			if index.tracks(root, tree) {
				b.Fatalf("%s reads as tracked", tree)
			}
		}
	}
}
