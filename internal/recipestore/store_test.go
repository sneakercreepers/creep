package recipestore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/recipe"
)

const commit = "0123456789abcdef0123456789abcdef01234567"

// testStore reads with os.Root.ReadFile, which reports fs.ErrNotExist as
// ReadFunc promises; cli supplies the non-blocking, link-refusing read.
func testStore() Store {
	return Store{
		Read: func(root *os.Root, _, name string, limit int64) ([]byte, error) {
			data, err := root.ReadFile(name)
			if err == nil && int64(len(data)) > limit {
				return nil, errors.New("too large")
			}
			return data, err
		},
		PoC: func(string, json.RawMessage) error { return nil },
	}
}

// isolatedHome points os.UserHomeDir at a new directory.
func isolatedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func source(t *testing.T) recipe.Source {
	t.Helper()
	src, err := recipe.ParseSource("github.com/acme/recipes@" + commit)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func installed(t *testing.T) string {
	t.Helper()
	home := isolatedHome(t)
	if err := testStore().Install(source(t), map[string][]byte{"sqli.json": recipe.Template()}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	return filepath.Join(home, filepath.FromSlash(Dir))
}

// Protection (ADR 0028): an installed recipe loads only as pinned and
// allowed; a changed, missing or disallowed one fails the whole load, and
// no store at all installs nothing.
func TestLoadVerifiesEveryPin(t *testing.T) {
	file := filepath.Join("acme", "recipes", commit, "sqli.json")
	tests := []struct {
		name   string
		change func(t *testing.T, dir string)
		policy Policy
		want   string // "" loads one recipe
	}{
		{"as installed", func(*testing.T, string) {}, Policy{}, ""},
		{"allowed by the policy", func(*testing.T, string) {}, Policy{Patterns: []string{"github.com/acme/*"}, Enforced: true}, ""},
		{"not allowed", func(*testing.T, string) {}, Policy{Enforced: true}, "recipe_sources allowlist"},
		{"file changed", func(t *testing.T, dir string) { write(t, filepath.Join(dir, file), "{}") }, Policy{}, "does not match creep.lock"},
		{"file missing", func(t *testing.T, dir string) { remove(t, filepath.Join(dir, file)) }, Policy{}, "is missing"},
		{"lock edited", func(t *testing.T, dir string) { write(t, filepath.Join(dir, recipe.LockFile), "{") }, Policy{}, "lock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := installed(t)
			tt.change(t, dir)
			got, err := testStore().Load(tt.policy)
			if tt.want == "" {
				if err != nil || len(got) != 1 {
					t.Fatalf("Load = %d recipes, %v; want 1", len(got), err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load error %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadWithoutStore(t *testing.T) {
	isolatedHome(t)
	if got, err := testStore().Load(Policy{}); err != nil || len(got) != 0 {
		t.Fatalf("no store: %d recipes, %v", len(got), err)
	}
}

// A clone is read only at the pinned commit of the pinned repository, from
// a real .git directory, with at least one valid recipe.
func TestReadCloneRefuses(t *testing.T) {
	good := map[string]string{
		".git/HEAD":         commit + "\n",
		".git/config":       "[remote \"origin\"]\n\turl = https://github.com/acme/recipes.git\n",
		"recipes/sqli.json": string(recipe.Template()),
	}
	tests := []struct {
		name   string
		change map[string]string // "" drops a file
		want   string            // "" reads one recipe
	}{
		{"good clone", nil, ""},
		{"other commit", map[string]string{".git/HEAD": strings.Repeat("f", 40) + "\n"}, "not detached at"},
		{"branch head", map[string]string{".git/HEAD": "ref: refs/heads/main\n"}, "not detached at"},
		{"other origin", map[string]string{".git/config": "[remote \"origin\"]\n\turl = https://github.com/evil/recipes.git\n"}, "remote origin"},
		{"no recipes", map[string]string{"recipes/sqli.json": "", "recipes/x.txt": "x"}, "no recipe files"},
		{"bad recipe", map[string]string{"recipes/sqli.json": "{}"}, "clone recipe"},
		{"bad file name", map[string]string{"recipes/Bad Name.json": string(recipe.Template())}, "whose name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range merge(good, tt.change) {
				write(t, filepath.Join(dir, filepath.FromSlash(name)), content)
			}
			files, err := testStore().ReadClone(dir, source(t))
			if tt.want == "" {
				if err != nil || len(files) != 1 {
					t.Fatalf("ReadClone = %d files, %v", len(files), err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ReadClone error %v, want %q", err, tt.want)
			}
		})
	}
}

func merge(base, change map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range change {
		out[k] = v
	}
	for k, v := range out {
		if v == "" {
			delete(out, k)
		}
	}
	return out
}

func write(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func remove(t *testing.T, name string) {
	t.Helper()
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
}
