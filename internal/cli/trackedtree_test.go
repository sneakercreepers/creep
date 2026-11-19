package cli

import (
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newTrackedIndex(tt.tracked).tracks(root, tt.dir); got != tt.want {
				t.Errorf("tracks(%q) with %q = %v, want %v", tt.dir, tt.tracked, got, tt.want)
			}
		})
	}
}
