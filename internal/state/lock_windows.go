//go:build windows

package state

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

const (
	// errSharingViolation is ERROR_SHARING_VIOLATION: another handle is open.
	errSharingViolation = syscall.Errno(32)
	// A virus scanner or indexer may hold the file for a moment; retrying a
	// few times keeps that from reading as a second creep, and stays bounded.
	lockAttempts = 5
	lockRetry    = 50 * time.Millisecond
)

// lockOpen opens the lock file with no sharing, so any second open (another
// creep process, or another run in this one) fails; lockOpen retries it
// lockAttempts times, lockRetry apart (about 200 ms). Even a stat of
// the file fails while it is held, so both count as "in use".
func (s *Store) lockOpen(name string) (*os.File, error) {
	for attempt := 1; ; attempt++ {
		f, err := s.lockOnce(name)
		if !errors.Is(err, errSharingViolation) {
			return f, err
		}
		if attempt == lockAttempts {
			return nil, ErrLocked
		}
		time.Sleep(lockRetry)
	}
}

// lockOnce opens the handle on a link itself, never through it, and only
// keeps it when it is the regular file the store's root sees under name.
func (s *Store) lockOnce(name string) (*os.File, error) {
	before, err := s.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	os.SameFile(before, before) // pin the file ID now, not at comparison time
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file: %w", name, ErrUnsafePath)
	}
	p, err := syscall.UTF16PtrFromString(s.abs(name))
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), name)
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, fmt.Errorf("%s changed while opening: %w", name, ErrUnsafePath)
	}
	return f, nil
}
