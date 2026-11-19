package state

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// lockFile is the state directory's inter-process lock. It is empty: only
// the OS lock on an open handle counts, and the OS drops that lock when the
// process exits, so a crash never leaves the directory locked.
const lockFile = "lock"

// ErrLocked means another open run holds the state directory: a second
// creep process (or a second run in this one) would interleave its appends
// with the first run's. Taking the lock never waits for the holder; Windows
// only retries a sharing violation for about 200 ms.
var ErrLocked = errors.New("state directory in use by another creep process; wait for it to finish")

// lock takes the store's exclusive lock without waiting. Closing the
// returned file releases it.
func (s *Store) lock() (*os.File, error) {
	if err := s.createLockFile(); err != nil {
		return nil, err
	}
	f, err := s.lockOpen(lockFile)
	if err != nil {
		return nil, fmt.Errorf("state dir %q: lock: %w", s.dir, err)
	}
	return f, nil
}

// createLockFile creates the lock file if missing. Anything already there
// (or a stat that fails because another creep holds the file) is left for
// lockOpen to refuse or lock; O_EXCL never opens an entry that appeared
// in between.
func (s *Store) createLockFile() error {
	if _, err := s.root.Lstat(lockFile); !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	f, err := s.root.OpenFile(lockFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL|nonblockFlag, fileMode)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("state dir %q: lock: %w", s.dir, err)
	}
	return f.Close()
}
