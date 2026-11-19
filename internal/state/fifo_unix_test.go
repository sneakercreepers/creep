//go:build unix

package state

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A FIFO in place of a state file is refused at once instead of blocking
// creep forever on open.
func TestFIFORefusedWithoutBlocking(t *testing.T) {
	s := openStore(t)
	r := newRun(t, s)
	_ = r.Close()
	events := filepath.Join(r.Dir(), eventsFile)
	if err := os.Remove(events); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(events, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if _, err := s.Resume(r.ID()); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("Resume of FIFO err = %v; want ErrUnsafePath", err)
	}

	k := testKey("x")
	if err := s.ensureDir(cacheDir); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(cachePath(s, k), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Lookup(k); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("Lookup of FIFO err = %v; want ErrUnsafePath", err)
	}
	calls := 0
	if got, err := s.Respond(ModeLive, k, countingCall("real", &calls)); err != nil || string(got) != "real" || calls != 1 {
		t.Errorf("live on a FIFO entry = %q, %v with %d calls; want the model's answer", got, err, calls)
	}

	lock := filepath.Join(s.dir, lockFile)
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(lock, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NewRun(ModeLive); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("NewRun with a FIFO lock err = %v; want ErrUnsafePath", err)
	}
}
