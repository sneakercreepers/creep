package gateway

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Security (#6 review L1, I1): no spelling of a program inside the
// repository runs: a junction from outside into it, a \\?\ verbatim path,
// a device path or a UNC share. A junction is named in the error.
func TestNewCommandRefusesWindowsPathsIntoRepo(t *testing.T) {
	repo, outside := t.TempDir(), t.TempDir()
	bin := filepath.Join(repo, "bin", "fakecli.exe")
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(outside, "j")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, filepath.Dir(bin)).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	viaJunction := filepath.Join(junction, "fakecli.exe")
	tests := []struct {
		name, program, want string
	}{
		{"verbatim", `\\?\` + bin, "inside the scanned repository"},
		{"junction", viaJunction, "follows a link or junction"},
		{"verbatim junction", `\\?\` + viaJunction, "follows a link or junction"},
		{"device", `\\.\` + bin, "device or network path"},
		{"unc", `\\creep-test.invalid\share\cli.exe`, "device or network path"},
		{"verbatim unc", `\\?\UNC\creep-test.invalid\share\cli.exe`, "device or network path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := fakeOptions(t, "echo", time.Second)
			opts.Run, opts.RepoDir = `"`+tt.program+`"`, repo
			_, err := NewCommand(opts)
			if !errors.Is(err, ErrCommand) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NewCommand(%s) = %v, want %q", tt.program, err, tt.want)
			}
		})
	}
}

// Protection (#229 auditor A4): a junction anywhere between the run
// directory and home is refused like a Unix link, as the cache directory
// itself or as an ancestor of it.
func TestRunRootRefusesJunctions(t *testing.T) {
	for _, nested := range []bool{false, true} {
		home, target := t.TempDir(), t.TempDir()
		if err := os.MkdirAll(filepath.Join(target, "cache"), 0o700); err != nil {
			t.Fatal(err)
		}
		junction := filepath.Join(home, "a")
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
			t.Fatalf("mklink: %v %s", err, out)
		}
		cache := junction
		if nested {
			cache = filepath.Join(junction, "cache")
		}
		useDirs(t, cache, home, nil)
		if root, err := newRunRoot(); !errors.Is(err, errUnsafeRunDir) {
			t.Errorf("nested=%v: newRunRoot() = %q, %v; want errUnsafeRunDir", nested, root, err)
		}
	}
}
