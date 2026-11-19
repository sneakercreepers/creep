package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// runDirCase is one cache and home layout newRunRoot must refuse.
type runDirCase struct {
	name  string
	setup func(t *testing.T) (cache, home string)
	err   error  // from the cache dir lookup
	only  string // "unix" or "linux" when the layout needs it
}

// Protection (#229 F3, G1, G2): a run directory is made only when every
// directory from it up to the home directory (or the volume root) is a real
// directory others cannot write to, and both user directories are absolute.
func TestRunRootRefusesUnsafeParents(t *testing.T) {
	for _, tt := range unsafeRunDirCases() {
		t.Run(tt.name, func(t *testing.T) {
			switch {
			case tt.only == "unix" && runtime.GOOS == "windows",
				tt.only == "linux" && runtime.GOOS != "linux":
				t.Skip("needs " + tt.only + " modes or links")
			}
			cache, home := tt.setup(t)
			useDirs(t, cache, home, tt.err)
			if root, err := newRunRoot(); err == nil {
				t.Errorf("newRunRoot() = %q, want an error", root)
			}
		})
	}
	useCacheDir(t, t.TempDir(), nil)
	if _, err := newRunRoot(); err != nil {
		t.Errorf("private cache dir refused: %v", err)
	}
}

func unsafeRunDirCases() []runDirCase {
	same := func(f func(*testing.T) string) func(*testing.T) (string, string) {
		return func(t *testing.T) (string, string) { d := f(t); return d, d }
	}
	return []runDirCase{
		{"no cache dir", same(func(*testing.T) string { return "" }), errors.New("$HOME is not defined"), ""},
		{"relative cache dir", func(*testing.T) (string, string) { return filepath.Join("repo", ".cache"), "repo" }, nil, ""},
		{"relative home", func(t *testing.T) (string, string) { return t.TempDir(), "repo" }, nil, ""},
		{"cache dir is a file", same(func(t *testing.T) string { return withEntry(t, "", "file") }), nil, ""},
		{"model dir is a file", same(func(t *testing.T) string { return withEntry(t, "creep/model", "file") }), nil, ""},
		{"model dir is a link", same(func(t *testing.T) string { return withEntry(t, "creep/model", "link") }), nil, "unix"},
		{"model dir open to others", same(func(t *testing.T) string { return withMode(t, "creep/model", 0o755) }), nil, "unix"},
		{"creep dir writable by others", same(func(t *testing.T) string { return withMode(t, "creep", 0o777) }), nil, "unix"},
		{"cache dir writable by others", same(func(t *testing.T) string { return withMode(t, ".", 0o777) }), nil, "unix"},
		{"cache dir is a link", underHome(false, "link", 0), nil, "unix"},
		{"ancestor is a link", underHome(true, "link", 0), nil, "unix"},
		{"ancestor writable by others", underHome(true, "mode", 0o777), nil, "unix"},
		{"ancestor sticky and writable by others", underHome(true, "mode", 0o777|os.ModeSticky), nil, "unix"},
		// Not under home: the walk reaches /tmp, which is 1777.
		{"cache outside home under /tmp", underSharedTemp, nil, "linux"},
	}
}

// underSharedTemp returns a private cache dir under /tmp and a home it is
// not under, so the walk reaches /tmp itself.
func underSharedTemp(t *testing.T) (string, string) {
	t.Helper()
	info, err := os.Stat(os.TempDir())
	if err != nil || os.TempDir() != "/tmp" || info.Mode().Perm()&0o002 == 0 {
		t.Skip("the system temp directory is not a shared /tmp")
	}
	return t.TempDir(), "/nonexistent-home"
}

// underHome makes home/a the top directory (a link to a real directory,
// or a directory with mode) and returns it, or home/a/cache when nested, as
// the cache dir.
func underHome(nested bool, kind string, mode os.FileMode) func(*testing.T) (string, string) {
	return func(t *testing.T) (string, string) {
		t.Helper()
		home := t.TempDir()
		top, cache := filepath.Join(home, "a"), filepath.Join(home, "a")
		if nested {
			cache = filepath.Join(top, "cache")
		}
		if kind == "link" {
			target := t.TempDir()
			if err := os.MkdirAll(filepath.Join(target, "cache"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, top); err != nil {
				t.Fatal(err)
			}
			return cache, home
		}
		if err := os.MkdirAll(cache, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(top, mode); err != nil {
			t.Fatal(err)
		}
		return cache, home
	}
}

// withEntry makes a cache dir whose <rel> ("" for the cache dir itself, in
// which case a file stands in for it) is a file or a link to a directory.
func withEntry(t *testing.T, rel, kind string) string {
	t.Helper()
	cache := t.TempDir()
	if rel == "" {
		file := filepath.Join(cache, "file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	path := filepath.Join(cache, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if kind == "file" {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return cache
	}
	if err := os.Symlink(t.TempDir(), path); err != nil {
		t.Fatal(err)
	}
	return cache
}

// withMode makes a cache dir with creep/model in place and rel set to mode.
func withMode(t *testing.T, rel string, mode os.FileMode) string {
	t.Helper()
	cache := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cache, "creep", "model"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cache, filepath.FromSlash(rel))
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return cache
}
