package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/recipe"
	"github.com/sneakercreepers/creep/internal/recipestore"
)

const (
	cloneCommit = "0123456789abcdef0123456789abcdef01234567"
	cloneSource = "github.com/acme/recipes"
	pinned      = cloneSource + "@" + cloneCommit
)

// cloneFiles is a clone of acme/recipes at cloneCommit with the template
// recipe; tests change or drop entries ("" drops one).
func cloneFiles() map[string]string {
	return map[string]string{
		".git/HEAD":         cloneCommit + "\n",
		".git/config":       "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/acme/recipes.git\n",
		"recipes/sqli.json": string(recipe.Template()),
		"recipes/README.md": "not a recipe; ignored\n",
	}
}

// makeClone writes files into a new directory outside the repository and
// returns its path.
func makeClone(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if content == "" {
			continue
		}
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, p, content)
	}
	return dir
}

// storeFile is a path under the isolated home's recipe store.
func storeFile(t *testing.T, name string) string {
	t.Helper()
	dir, ok := recipestore.Path()
	if !ok {
		t.Fatal("no home directory")
	}
	return filepath.Join(dir, filepath.FromSlash(name))
}

// installTemplate runs `creep recipe add` on a good clone and fails the
// test unless it installs.
func installTemplate(t *testing.T) {
	t.Helper()
	if code, out, stderr := run("recipe", "add", pinned, makeClone(t, cloneFiles())); code != exitcode.OK {
		t.Fatalf("recipe add: exit %d: %s%s", code, out, stderr)
	}
}

// An install copies the clone's recipe files into ~/.creep/recipes and
// pins each with its checksum; a later commit replaces the earlier one.
func TestRecipeAddInstallsPinned(t *testing.T) {
	scanRepo(t, nil, "")
	code, out, stderr := run("recipe", "add", pinned, makeClone(t, cloneFiles()))
	if code != exitcode.OK || !strings.Contains(out, "installed 1 recipe files from "+pinned) {
		t.Fatalf("recipe add: exit %d: %s%s", code, out, stderr)
	}
	data, err := os.ReadFile(storeFile(t, recipe.LockFile))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := recipe.ParseLock(data)
	if err != nil || len(lock.Recipes) != 1 {
		t.Fatalf("lock = %+v, %v", lock, err)
	}
	want := recipe.Pin{Source: cloneSource, Commit: cloneCommit, File: "sqli.json", Checksum: recipe.Checksum(recipe.Template())}
	if lock.Recipes[0] != want {
		t.Errorf("pin = %+v, want %+v", lock.Recipes[0], want)
	}
	if got, err := os.ReadFile(storeFile(t, want.Path())); err != nil || string(got) != string(recipe.Template()) {
		t.Errorf("installed file: %v", err)
	}
	next := strings.Repeat("b", 40)
	files := cloneFiles()
	files[".git/HEAD"] = next + "\n"
	if code, _, stderr := run("recipe", "add", cloneSource+"@"+next, makeClone(t, files)); code != exitcode.OK {
		t.Fatalf("second add: exit %d: %s", code, stderr)
	}
	if _, err := os.Stat(storeFile(t, want.Path())); !os.IsNotExist(err) {
		t.Errorf("the replaced commit's file is still installed: %v", err)
	}
	if _, err := loadInstalledRecipes(mustResolve(t)); err != nil {
		t.Errorf("the reinstalled lock does not verify: %v", err)
	}
}

// TestRecipeAddRefuses: a branch, tag or short SHA, a clone at another
// commit or of another repository, and a recipe that breaks the format
// install nothing and exit 2.
func TestRecipeAddRefuses(t *testing.T) {
	tests := []struct {
		name   string
		source string
		change map[string]string // clone files to set; "" drops one
		want   string
	}{
		{"branch", cloneSource + "@main", nil, "branch names, tags and short SHAs are refused"},
		{"tag", cloneSource + "@v1.0.0", nil, "branch names, tags and short SHAs are refused"},
		{"short sha", cloneSource + "@0123456", nil, "full 40-hex"},
		{"no pin", cloneSource, nil, "full 40-hex"},
		{"other host", "gitlab.com/acme/recipes@" + cloneCommit, nil, "github.com"},
		{"symbolic HEAD", pinned, map[string]string{".git/HEAD": "ref: refs/heads/main\n"}, "HEAD is not detached"},
		{"HEAD at another commit", pinned, map[string]string{".git/HEAD": strings.Repeat("c", 40) + "\n"}, "HEAD is not detached"},
		{"no HEAD", pinned, map[string]string{".git/HEAD": ""}, "HEAD"},
		{"other origin", pinned, map[string]string{".git/config": "[remote \"origin\"]\n\turl = https://github.com/evil/recipes.git\n"}, "remote origin"},
		{"no origin", pinned, map[string]string{".git/config": "[core]\n"}, "remote origin"},
		{"no recipes", pinned, map[string]string{"recipes/sqli.json": ""}, "no recipe files"},
		{"invalid recipe", pinned, map[string]string{"recipes/bad.json": `{"version": 2}`}, "recipe refused"},
		{"bad file name", pinned, map[string]string{"recipes/Bad Name.json": string(recipe.Template())}, "name"},
		{"oversized recipe", pinned, map[string]string{"recipes/big.json": strings.Repeat(" ", recipe.MaxFileBytes+1)}, "big"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanRepo(t, nil, "")
			files := cloneFiles()
			for k, v := range tt.change {
				files[k] = v
			}
			code, out, stderr := run("recipe", "add", tt.source, makeClone(t, files))
			if code != exitcode.ConfigError || !strings.Contains(stderr, tt.want) || strings.Contains(out, "installed") {
				t.Errorf("exit %d, want 2 and %q: %s%s", code, tt.want, out, stderr)
			}
			if _, err := os.Stat(storeFile(t, recipe.LockFile)); !os.IsNotExist(err) {
				t.Errorf("a refused add wrote creep.lock: %v", err)
			}
		})
	}
}

// A clone whose .git or recipes directory is a link or a file, the
// layout of a worktree or a planted redirect, is refused.
func TestRecipeAddRefusesLinkedClone(t *testing.T) {
	scanRepo(t, nil, "")
	real := makeClone(t, cloneFiles())
	worktree := makeClone(t, map[string]string{".git": "gitdir: " + filepath.Join(real, ".git") + "\n", "recipes/sqli.json": string(recipe.Template())})
	if code, _, stderr := run("recipe", "add", pinned, worktree); code != exitcode.ConfigError || !strings.Contains(stderr, ".git must be a directory") {
		t.Errorf(".git file: exit %d: %s", code, stderr)
	}
	linked := makeClone(t, map[string]string{".git/HEAD": cloneCommit + "\n", ".git/config": cloneFiles()[".git/config"]})
	linkDir(t, filepath.Join(real, "recipes"), filepath.Join(linked, "recipes"))
	if code, _, stderr := run("recipe", "add", pinned, linked); code != exitcode.ConfigError || !strings.Contains(stderr, "recipes must be a directory") {
		t.Errorf("linked recipes/: exit %d: %s", code, stderr)
	}
}

// Usage errors of add never exit 0.
func TestRecipeAddUsage(t *testing.T) {
	scanRepo(t, nil, "")
	for _, args := range [][]string{{"recipe", "add"}, {"recipe", "add", pinned}, {"recipe", "add", pinned, "a", "b"}} {
		if code, _, stderr := run(args...); code != exitcode.ConfigError || !strings.Contains(stderr, "creep recipe add") {
			t.Errorf("%v: exit %d: %s", args, code, stderr)
		}
	}
	if code, _, stderr := runScanWith(fakeDeps(rightRecipeModel(), calibrate.TierM), "recipe", "add", pinned, filepath.Join(t.TempDir(), "missing")); code != exitcode.ConfigError || stderr == "" {
		t.Errorf("missing clone: exit %d: %s", code, stderr)
	}
}

// mustResolve loads the config as a command would.
func mustResolve(t *testing.T) *config.Resolved {
	t.Helper()
	r, err := loadConfig(globalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
