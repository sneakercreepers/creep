package state

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Regression (#209): OpenExisting, which creep why reads through, refuses
// what Open refuses and never creates the directory.
func TestOpenExistingRefusesUnsafeDir(t *testing.T) {
	tests := []struct {
		name   string
		plant  func(t *testing.T, dir string)
		unsafe bool // want ErrUnsafePath; otherwise want success
	}{
		{"directory", func(t *testing.T, dir string) { mustMkdir(t, dir, 0o700) }, false},
		{"file", func(t *testing.T, dir string) {
			if err := os.WriteFile(dir, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"link to a directory", func(t *testing.T, dir string) {
			target := filepath.Join(t.TempDir(), "elsewhere")
			mustMkdir(t, target, 0o700)
			if err := os.Symlink(target, dir); err != nil {
				t.Skipf("symlink unsupported here: %v", err)
			}
		}, true},
		{"writable by others", func(t *testing.T, dir string) {
			if runtime.GOOS == "windows" {
				t.Skip("mode bits are not ACLs on Windows")
			}
			mustMkdir(t, dir, 0o700)
			if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // G302: the test needs a world-writable dir to prove it is refused
				t.Fatal(err)
			}
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), ".creep")
			tt.plant(t, dir)
			root, err := OpenExisting(dir)
			if root != nil {
				_ = root.Close()
			}
			if tt.unsafe != errors.Is(err, ErrUnsafePath) || (!tt.unsafe && err != nil) {
				t.Fatalf("OpenExisting err = %v, want unsafe %v", err, tt.unsafe)
			}
		})
	}
	missing := filepath.Join(t.TempDir(), ".creep")
	if _, err := OpenExisting(missing); err == nil {
		t.Fatal("OpenExisting opened a missing directory")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("OpenExisting created %s: %v", missing, err)
	}
}

// The race the Lstat leaves (#209): a directory swapped in under the name
// after it was checked is not the one checked, and is refused; the same
// directory opens.
func TestOpenSameDirRefusesSwap(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dir")
	mustMkdir(t, dir, 0o700)
	before, err := checkDir(dir, os.Lstat)
	if err != nil {
		t.Fatal(err)
	}
	root, err := openSameDir(dir, before)
	if err != nil {
		t.Fatalf("same directory refused: %v", err)
	}
	_ = root.Close()
	if err := os.Rename(dir, dir+".checked"); err != nil {
		t.Fatal(err)
	}
	mustMkdir(t, dir, 0o700)
	if root, err := openSameDir(dir, before); !errors.Is(err, ErrUnsafePath) {
		if root != nil {
			_ = root.Close()
		}
		t.Fatalf("swapped directory opened: %v", err)
	}
}

func mustMkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(dir, mode); err != nil {
		t.Fatal(err)
	}
}
