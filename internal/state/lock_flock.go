//go:build unix && !solaris && !aix

package state

import (
	"errors"
	"os"
	"syscall"
)

// lockOpen opens the lock file without following a link or blocking on a
// FIFO and takes a non-blocking flock on it. flock belongs to the open file,
// so a second open in this process conflicts too.
func (s *Store) lockOpen(name string) (*os.File, error) {
	f, err := s.openRegular(name, false)
	if err != nil {
		return nil, err
	}
	if err := flock(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func flock(f *os.File) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	err = raw.Control(func(fd uintptr) {
		lockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // G115: a file descriptor fits in an int
	})
	if err != nil {
		return err
	}
	if errors.Is(lockErr, syscall.EWOULDBLOCK) {
		return ErrLocked
	}
	return lockErr
}
