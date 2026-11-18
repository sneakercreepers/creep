//go:build unix

package cli

import (
	"os"
	"syscall"
)

// openForCheck opens path without blocking: a plain open of a FIFO waits for a
// writer forever, so creep would hang before it could reject the file.
func openForCheck(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G703: opening the path the user or CREEP_POLICY names is the point; checkConfigPath vets it first
}

// openNoFollow is openForCheck that fails on a final symlink (ELOOP), so a
// link swapped in after the Lstat check is never followed.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: the fixed project file name in the working directory; openProjectConfig vets the opened file
}

// linkCount reports how many directory entries name the file; more than one
// means a hard link whose other name may sit outside the repository.
func linkCount(info os.FileInfo) uint64 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 1
	}
	return uint64(st.Nlink) // Nlink is uint16 on darwin and uint32 on linux/arm64
}

// openInRoot opens name inside root without blocking, for files of the
// scanned repository and of .creep: either can hold a planted FIFO.
func openInRoot(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// restoreBlocking puts a file that passed the regular-file check back into
// blocking mode so later reads behave like a plain os.Open.
func restoreBlocking(f *os.File) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = conn.Control(func(fd uintptr) {
		setErr = syscall.SetNonblock(int(fd), false)
	})
	if err != nil {
		return err
	}
	return setErr
}
