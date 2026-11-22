//go:build unix && !aix && !solaris

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

// TestConfigRejectsFIFO guards against a hang: opening a FIFO with no writer
// blocks, so the check must not wait for one, directly or via a symlink.
func TestConfigRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "creep.yaml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, link} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			code, stderr := runWithTimeout(t, "--config", path, "version")
			if code != exitcode.ConfigError {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitcode.ConfigError, stderr)
			}
			assertContains(t, "stderr", stderr, []string{"not a regular file"})
		})
	}
}

// A FIFO planted as .creep/report.json is refused at once (#209): why never
// waits for a writer, and exits 2.
func TestWhyRejectsFIFOReport(t *testing.T) {
	isolateUserConfig(t)
	t.Chdir(t.TempDir())
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(stateDir, "report.json"), 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	code, stderr := runWithTimeout(t, "why", "sink-1")
	if code != exitcode.ConfigError {
		t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitcode.ConfigError, stderr)
	}
	assertContains(t, "stderr", stderr, []string{"not a regular file"})
}

// Protection (#26, R22): a --changed list that is a FIFO, or a link to
// one, is refused at once (exit 2) and never waits for a writer.
func TestChangedListRejectsFIFO(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "print(1)\n"}, "")
	dir := t.TempDir()
	fifo := filepath.Join(dir, "changed.txt")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, link} {
		code, _, stderr := scanWithTimeout(t, "scan", "--changed", path, "--config", cfg)
		if code != exitcode.ConfigError || !strings.Contains(stderr, "not a regular file") {
			t.Errorf("%s: exit %d, want %d with not a regular file\n%s", path, code, exitcode.ConfigError, stderr)
		}
	}
}

// Protection (#26, R8): a FIFO in the tree that the list names is never
// opened; the walk lists it not_regular, so the run is incomplete.
func TestChangedListNamingFIFO(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "print(1)\n"}, "")
	if err := syscall.Mkfifo("pipe.py", 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	code, out, stderr := scanWithTimeout(t, "scan", "--changed", changedListFile(t, "pipe.py\n"), "--config", cfg)
	if code != exitcode.Incomplete || !strings.Contains(out, "pipe.py  not_regular") {
		t.Errorf("exit %d, want %d with pipe.py not_regular\n%s\n%s", code, exitcode.Incomplete, out, stderr)
	}
}

func scanWithTimeout(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		code, stdout, stderr = runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), args...)
	}()
	select {
	case <-done:
		return code, stdout, stderr
	case <-time.After(10 * time.Second):
		t.Fatalf("creep %v hung", args)
		return 0, "", ""
	}
}

func runWithTimeout(t *testing.T, args ...string) (int, string) {
	t.Helper()
	type result struct {
		code   int
		stderr string
	}
	done := make(chan result, 1)
	go func() {
		code, _, stderr := run(args...)
		done <- result{code, stderr}
	}()
	select {
	case r := <-done:
		return r.code, r.stderr
	case <-time.After(5 * time.Second):
		t.Fatalf("creep %v hung", args)
		return 0, ""
	}
}

// A FIFO or a hard link planted where the baseline is: the scan exits 2 at
// once, never waiting for a writer and never reading the link's other name,
// which may sit outside the repository.
func TestBaselineSpecialFileRefused(t *testing.T) {
	tests := []struct {
		name string
		make func(t *testing.T, path string) error
		want string
	}{
		{"fifo", func(_ *testing.T, path string) error { return syscall.Mkfifo(path, 0o600) }, "not a link or special file"},
		{"hard link", func(t *testing.T, path string) error {
			outside := filepath.Join(t.TempDir(), "outside.json")
			mustWrite(t, outside, emptyBaseline)
			return os.Link(outside, path)
		}, "must not be a hard link"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			if err := tt.make(t, "b.json"); err != nil {
				t.Skipf("unsupported here: %v", err)
			}
			done := make(chan struct{})
			var code int
			var stderr string
			go func() {
				defer close(done)
				code, _, stderr = runScanWith(baselineDeps(vulnerableSQL(), baselineToday), "scan", "--config", cfg, "--baseline", "b.json")
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the scan hung on the baseline")
			}
			if code != exitcode.ConfigError || !strings.Contains(stderr, tt.want) {
				t.Errorf("exit %d: %s", code, stderr)
			}
		})
	}
}

// A FIFO planted where a recipe is named is refused at once: no recipe
// command waits for a writer.
func TestRecipeRefusesFIFO(t *testing.T) {
	scanRepo(t, nil, "")
	if err := syscall.Mkfifo("f.json", 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	for _, sub := range []string{"lint", "test", "new"} {
		if code, stderr := runRecipeWithin(t, sub, "f.json"); code != exitcode.ConfigError {
			t.Errorf("recipe %s on a FIFO: exit %d: %s", sub, code, stderr)
		}
	}
}
