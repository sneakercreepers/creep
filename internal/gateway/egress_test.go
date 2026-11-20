package gateway

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Acceptance: egress.log and payload files are created 0600 and the payload
// directory 0700. Skipped on Windows, where Go file modes do not reflect
// ACLs; the Linux CI job and the -race docker run cover it.
func TestFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file modes do not express ACLs; checked on Linux")
	}
	srv := newModelServer(t, "ok")
	dir := runDir(t)
	l := openLog(t, dir)
	reply, err := l.Send(context.Background(), srv.client(t), testCall(srv.url("/v1")))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	want := map[string]fs.FileMode{
		egressLogName:  0o600,
		payloadDirName: 0o700,
		filepath.Join(payloadDirName, reply.ID+".payload"): 0o600,
	}
	for name, mode := range want {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s mode = %v, want %v", name, info.Mode().Perm(), mode)
		}
	}
}

// An existing private log is appended to, never truncated.
func TestReopenAppends(t *testing.T) {
	dir := runDir(t)
	path := filepath.Join(dir, egressLogName)
	if err := os.WriteFile(path, []byte("{\"old\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := openLog(t, dir)
	if err := l.writeLine(map[string]int{"new": 2}); err != nil {
		t.Fatal(err)
	}
	if lines := readLines(t, dir); len(lines) != 2 || lines[0]["old"] != 1.0 {
		t.Fatalf("lines = %v; want old line kept", lines)
	}
}

// The log refuses paths an attacker could have prepared, each with
// ErrUnsafeLogPath from its own check: a private (0600) file as the run or
// payload directory passes the mode checks, so only the directory check
// refuses it, and removing that check fails this test on every OS (#113).
func TestOpenRefusesUnsafePaths(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, dir string) string // returns the run dir to open
		unix    bool                                  // relies on file modes
		want    error
	}{
		{"run dir missing", func(_ *testing.T, dir string) string { return filepath.Join(dir, "none") }, false, fs.ErrNotExist},
		{"run dir is a private file", func(t *testing.T, dir string) string { return writeFile(t, dir, "f", 0o600) }, false, ErrUnsafeLogPath},
		{"run dir is a symlink", symlinkRunDir, false, ErrUnsafeLogPath},
		{"payloads is a private file", func(t *testing.T, dir string) string { writeFile(t, dir, payloadDirName, 0o600); return dir }, false, ErrUnsafeLogPath},
		{"payloads is a symlink", symlinkPayloads, false, ErrUnsafeLogPath},
		{"payloads links inside the run dir", symlinkPayloadsInside, false, ErrUnsafeLogPath},
		{"log is a directory", func(t *testing.T, dir string) string { mkdir(t, dir, egressLogName); return dir }, false, ErrUnsafeLogPath},
		{"log is a symlink", symlinkLog, false, ErrUnsafeLogPath},
		{"log readable by others", func(t *testing.T, dir string) string { writeFile(t, dir, egressLogName, 0o644); return dir }, true, ErrUnsafeLogPath},
		{"run dir writable by others", func(t *testing.T, dir string) string { chmod(t, dir, 0o777); return dir }, true, ErrUnsafeLogPath},
		{"payloads readable by others", func(t *testing.T, dir string) string { chmod(t, mkdir(t, dir, payloadDirName), 0o755); return dir }, true, ErrUnsafeLogPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unix && runtime.GOOS == "windows" {
				t.Skip("Windows file modes do not express ACLs")
			}
			dir := tt.prepare(t, runDir(t))
			l, err := OpenEgressLog(dir, nil, nil)
			if err == nil {
				_ = l.Close()
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("OpenEgressLog: err = %v, want %v", err, tt.want)
			}
		})
	}
}

// symlinkRunDir returns a link to a private directory as the run directory.
func symlinkRunDir(t *testing.T, dir string) string {
	link := filepath.Join(t.TempDir(), "run-link")
	symlink(t, dir, link)
	return link
}

// symlinkPayloadsInside points payloads at a private directory in the run
// directory, which an os.Root alone would follow.
func symlinkPayloadsInside(t *testing.T, dir string) string {
	symlink(t, mkdir(t, dir, "elsewhere"), filepath.Join(dir, payloadDirName))
	return dir
}

func TestUnsafePathError(t *testing.T) {
	dir := runDir(t)
	mkdir(t, dir, egressLogName)
	if _, err := OpenEgressLog(dir, nil, nil); !errors.Is(err, ErrUnsafeLogPath) {
		t.Fatalf("err = %v, want ErrUnsafeLogPath", err)
	}
}

// symlinkLog points egress.log at a file outside the run directory, the
// way a hostile checkout or another process could redirect writes.
func symlinkLog(t *testing.T, dir string) string {
	target := writeFile(t, t.TempDir(), "victim", 0o600)
	symlink(t, target, filepath.Join(dir, egressLogName))
	return dir
}

func symlinkPayloads(t *testing.T, dir string) string {
	symlink(t, t.TempDir(), filepath.Join(dir, payloadDirName))
	return dir
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
}

func writeFile(t *testing.T, dir, name string, mode fs.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("{}\n"), mode); err != nil {
		t.Fatal(err)
	}
	chmod(t, p, mode) // WriteFile's mode is narrowed by umask
	return p
}

func mkdir(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func chmod(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// Swaps between the Lstat of egress.log and its open are refused: a new log
// needs O_EXCL, an existing one the same-file check.
func TestOpenRace(t *testing.T) {
	tests := []struct {
		name     string
		existing bool
	}{
		{"file appears after Lstat", false},
		{"file replaced after Lstat", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := runDir(t)
			if tt.existing {
				writeFile(t, dir, egressLogName, 0o600)
			}
			other := writeFile(t, t.TempDir(), "other", 0o600)
			setOpenHook(t, func(path string) {
				if err := os.Rename(other, path); err != nil {
					t.Fatal(err)
				}
			})
			if l, err := OpenEgressLog(dir, nil, nil); err == nil {
				_ = l.Close()
				t.Fatal("OpenEgressLog: want error")
			}
		})
	}
}

func setOpenHook(t *testing.T, hook func(string)) {
	t.Helper()
	old := testHookBeforeOpen
	testHookBeforeOpen = hook
	t.Cleanup(func() { testHookBeforeOpen = old })
}

func setDirOpenHook(t *testing.T, hook func(string)) {
	t.Helper()
	old := testHookBeforeDirOpen
	testHookBeforeDirOpen = hook
	t.Cleanup(func() { testHookBeforeDirOpen = old })
}

// A directory swapped in at the run or payload directory's path between its
// Lstat and its open is refused by the same-directory check (#113).
func TestDirSwapRefused(t *testing.T) {
	tests := []struct {
		name   string
		target func(dir string) string
	}{
		{"run dir", func(dir string) string { return dir }},
		{"payloads", func(dir string) string { return filepath.Join(dir, payloadDirName) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := runDir(t)
			target := tt.target(dir)
			setDirOpenHook(t, func(path string) {
				if path == target {
					swapDir(t, path)
				}
			})
			l, err := OpenEgressLog(dir, nil, nil)
			if err == nil {
				_ = l.Close()
			}
			if !errors.Is(err, ErrUnsafeLogPath) {
				t.Fatalf("err = %v, want ErrUnsafeLogPath", err)
			}
		})
	}
}

// swapDir moves the directory at path aside and creates a new private one
// in its place.
func swapDir(t *testing.T, path string) {
	t.Helper()
	if err := os.Rename(path, filepath.Join(t.TempDir(), "moved")); err != nil {
		t.Fatal(err)
	}
	mkdir(t, filepath.Dir(path), filepath.Base(path))
}

// Acceptance (#113): the run directory is resolved by path once. Moving it
// away and planting another directory (with its own payloads) at its path
// after it is opened changes nothing: payloads and egress.log are used in
// the directory first opened, never in the planted one. Windows cannot
// rename a directory while creep holds a handle on it, so the swap is
// impossible there and the test skips; Linux CI runs it.
func TestRunDirResolvedOnce(t *testing.T) {
	stages := []struct {
		name string
		arm  func(t *testing.T, swap func(string))
	}{
		{"before payloads", func(t *testing.T, swap func(string)) {
			setDirOpenHook(t, func(path string) {
				if filepath.Base(path) == payloadDirName {
					swap(path)
				}
			})
		}},
		{"before egress.log", func(t *testing.T, swap func(string)) { setOpenHook(t, swap) }},
	}
	for _, st := range stages {
		t.Run(st.name, func(t *testing.T) {
			dir := runDir(t)
			moved := filepath.Join(t.TempDir(), "moved")
			st.arm(t, func(string) { plantRunDir(t, dir, moved) })
			l, err := OpenEgressLog(dir, nil, nil)
			if err != nil {
				t.Fatalf("OpenEgressLog: %v", err)
			}
			t.Cleanup(func() { _ = l.Close() })
			payload, err := l.writePayload("swap", []byte("x"))
			if err != nil {
				t.Fatalf("writePayload: %v", err)
			}
			for _, name := range []string{egressLogName, payload} {
				if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("planted directory got %s (err = %v)", name, err)
				}
				if _, err := os.Lstat(filepath.Join(moved, name)); err != nil {
					t.Errorf("%s not in the directory first opened: %v", name, err)
				}
			}
		})
	}
}

// plantRunDir moves the run directory to moved and plants a private one,
// with an empty payloads directory, at its path.
func plantRunDir(t *testing.T, dir, moved string) {
	if err := os.Rename(dir, moved); err != nil {
		t.Skipf("cannot move an open directory here: %v", err)
	}
	mkdir(t, filepath.Dir(dir), filepath.Base(dir))
	mkdir(t, dir, payloadDirName)
}

// A log with a second hard link is refused on every OS: the count is read
// from the open handle, on Windows too (#113). Another owner is Unix only.
func TestOpenRefusesSharedLog(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, log string)
	}{
		{"second hard link", func(t *testing.T, log string) {
			if err := os.Link(log, filepath.Join(t.TempDir(), "alias")); err != nil {
				t.Skipf("hard links unsupported: %v", err)
			}
		}},
		{"other owner", func(t *testing.T, log string) {
			if runtime.GOOS == "windows" {
				t.Skip("Windows files have no Unix owner; see checkAccess")
			}
			if os.Geteuid() != 0 {
				t.Skip("chown to another user needs root; the docker -race run covers it")
			}
			if err := os.Chown(log, 65534, 65534); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := runDir(t)
			tt.prepare(t, writeFile(t, dir, egressLogName, 0o600))
			if _, err := OpenEgressLog(dir, nil, nil); !errors.Is(err, ErrUnsafeLogPath) {
				t.Fatalf("err = %v, want ErrUnsafeLogPath", err)
			}
		})
	}
}

// A log left without a final newline by a torn write gets its next line on
// a fresh line.
func TestTornLineRecovered(t *testing.T) {
	dir := runDir(t)
	if err := os.WriteFile(filepath.Join(dir, egressLogName), []byte(`{"torn":`), 0o600); err != nil {
		t.Fatal(err)
	}
	l := openLog(t, dir)
	if err := l.writeLine(map[string]int{"next": 1}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, egressLogName))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{\"torn\":\n{\"next\":1}\n" {
		t.Fatalf("log = %q; want the new line after a newline", raw)
	}
}
