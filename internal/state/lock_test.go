package state

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// lockDeadline is far above the bounded retry on Windows (about 200 ms): a
// lock attempt that takes longer is a hang, not a refusal.
const lockDeadline = 5 * time.Second

// openRun opens one run on s for the cases below: a new one, or a resume of
// the interrupted run id.
type openRun func(s *Store, id string) (*Run, error)

func openNew(s *Store, _ string) (*Run, error)  { return s.NewRun(ModeLive) }
func openOld(s *Store, id string) (*Run, error) { return s.Resume(id) }

// While a run is open, every other run on the same directory fails at once
// with ErrLocked, whether it is new or a resume, through the same store or a
// second one; after Close the directory is free again and the first log
// still loads.
func TestLockRefusesSecondRun(t *testing.T) {
	tests := []struct {
		name          string
		first, second openRun
		sameStore     bool
	}{
		{"new then new", openNew, openNew, true},
		{"new then resume", openNew, openOld, true},
		{"resume then new", openOld, openNew, true},
		{"resume then resume", openOld, openOld, true},
		{"second store", openNew, openNew, false},
		{"second store resumes", openNew, openOld, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openStore(t)
			id := interruptedRun(t, s)
			first, err := tt.first(s, id)
			if err != nil {
				t.Fatal(err)
			}
			if err := first.StepDone("first"); err != nil {
				t.Fatal(err)
			}
			other := s
			if !tt.sameStore {
				other = reopen(t, s)
			}
			start := time.Now()
			if r, err := tt.second(other, id); !errors.Is(err, ErrLocked) {
				if r != nil {
					_ = r.Close()
				}
				t.Fatalf("second run err = %v; want ErrLocked", err)
			}
			if d := time.Since(start); d > lockDeadline {
				t.Fatalf("refusal took %v; want no wait", d)
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			if sum, err := s.Load(first.ID()); err != nil || !slices.Contains(sum.Steps, "first") {
				t.Fatalf("first log after refusal = %+v, %v; want it intact", sum, err)
			}
			free, err := tt.second(other, id)
			if err != nil {
				t.Fatalf("after Close, second run err = %v", err)
			}
			_ = free.Close()
		})
	}
}

// A refused or failed open releases the lock, so it never wedges the
// directory for the rest of the process.
func TestFailedOpenReleasesLock(t *testing.T) {
	s := openStore(t)
	ended := newRun(t, s)
	if err := ended.Finish(OutcomeComplete, ""); err != nil {
		t.Fatal(err)
	}
	_ = ended.Close()
	if _, err := s.Resume(ended.ID()); !errors.Is(err, ErrRunEnded) {
		t.Fatalf("Resume of ended run err = %v; want ErrRunEnded", err)
	}
	if _, err := s.Resume("20260101T000000Z-00000000"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Resume of missing run err = %v; want not exist", err)
	}
	runs := filepath.Join(s.dir, runsDir)
	if err := os.Rename(runs, runs+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runs, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NewRun(ModeLive); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("NewRun with runs as a file err = %v; want ErrUnsafePath", err)
	}
	if err := os.Remove(runs); err != nil {
		t.Fatal(err)
	}
	r := newRun(t, s)
	_ = r.Close()
}

// A planted lock that is not a regular file is refused, never followed, and
// refused at once.
func TestLockFileMustBeRegular(t *testing.T) {
	tests := []struct {
		name  string
		plant func(lock, target string) error
	}{
		{"directory", func(lock, _ string) error { return os.Mkdir(lock, 0o700) }},
		{"link to a file", func(lock, target string) error { return os.Symlink(target, lock) }},
		{"dangling link", func(lock, target string) error { return os.Symlink(target+".missing", lock) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openStore(t)
			target := filepath.Join(t.TempDir(), "elsewhere")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tt.plant(filepath.Join(s.dir, lockFile), target); err != nil {
				t.Skipf("plant: %v", err)
			}
			start := time.Now()
			if _, err := s.NewRun(ModeLive); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("NewRun err = %v; want ErrUnsafePath", err)
			}
			if d := time.Since(start); d > lockDeadline {
				t.Fatalf("refusal took %v", d)
			}
		})
	}
}

// interruptedRun creates a closed run without an end line and returns its ID.
func interruptedRun(t *testing.T, s *Store) string {
	t.Helper()
	r := newRun(t, s)
	_ = r.Close()
	return r.ID()
}

// reopen opens a second store on s's directory.
func reopen(t *testing.T, s *Store) *Store {
	t.Helper()
	other, err := Open(s.dir, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	return other
}
