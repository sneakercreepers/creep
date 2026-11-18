package cli

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestProjectConfigSwapAfterCheck replays the race of #63 deterministically:
// the path passes the Lstat check, is swapped, and only then opened.
func TestProjectConfigSwapAfterCheck(t *testing.T) {
	tests := []struct {
		name    string
		swap    func(t *testing.T, path string)
		wantErr string
	}{
		{"unchanged is accepted", func(*testing.T, string) {}, ""},
		{"symlink swapped in", swapToSymlink, "link"},
		{"regular file swapped in", swapToOtherFile, "changed while being opened"},
		{"hard link swapped in", swapToHardLink, "changed while being opened"},
		{"removed", func(t *testing.T, path string) { mustRemove(t, path) }, "does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), projectFile)
			mustWrite(t, path, "log:\n  level: warn\n")
			before, err := lstatNoLink("project config", path)
			if err != nil {
				t.Fatal(err)
			}
			tt.swap(t, path)
			f, _, err := openSameFile("project config", path, before)
			assertOpenResult(t, f, err, tt.wantErr)
		})
	}
}

// TestProjectConfigRejectsHardLink covers a hard link already in place: its
// other name may be a file outside the repository.
func TestProjectConfigRejectsHardLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("FileInfo carries no link count on Windows; the swap checks still apply")
	}
	dir := t.TempDir()
	outside := filepath.Join(dir, "secret.yaml")
	mustWrite(t, outside, "log:\n  level: warn\n")
	path := filepath.Join(dir, projectFile)
	if err := os.Link(outside, path); err != nil {
		t.Skipf("hard links unsupported here: %v", err)
	}
	f, _, err := openProjectConfig("project config", path)
	assertOpenResult(t, f, err, "must not be a hard link")
}

func assertOpenResult(t *testing.T, f *os.File, err error, wantErr string) {
	t.Helper()
	if wantErr == "" {
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		f.Close()
		return
	}
	if err == nil {
		f.Close()
		t.Fatalf("opened a swapped file, want error containing %q", wantErr)
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("err = %v, want containing %q", err, wantErr)
	}
}

func swapToSymlink(t *testing.T, path string) {
	target := filepath.Join(t.TempDir(), "secret.yaml")
	mustWrite(t, target, "log:\n  level: warn\n")
	mustRemove(t, path)
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
}

func swapToOtherFile(t *testing.T, path string) {
	other := path + ".new"
	mustWrite(t, other, "log:\n  level: warn\n")
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
}

// swapToHardLink replaces the checked file with a second name of a file
// elsewhere; the file ID differs from the checked one on every OS.
func swapToHardLink(t *testing.T, path string) {
	target := filepath.Join(filepath.Dir(path), "secret.yaml")
	mustWrite(t, target, "log:\n  level: warn\n")
	mustRemove(t, path)
	if err := os.Link(target, path); err != nil {
		t.Skipf("hard links unsupported here: %v", err)
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
