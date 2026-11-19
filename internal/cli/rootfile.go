package cli

import (
	"errors"
	"io"
	"os"
)

// errFileTooLarge means a file is over the reader's limit; it is refused,
// never truncated.
var errFileTooLarge = errors.New("file too large")

// readInRoot reads the regular file name inside root, at most limit bytes.
// root confines the open to the directory, so a link in the scanned
// repository or in .creep cannot point the read elsewhere, and the open does
// not block on a FIFO.
func readInRoot(root *os.Root, name string, limit int64) ([]byte, error) {
	f, info, err := openRegularInRoot(root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info.Size() > limit {
		return nil, errFileTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errFileTooLarge
	}
	return data, nil
}

// readHeadInRoot reads at most n bytes from the start of the regular file
// name inside root, with the same confinement as readInRoot.
func readHeadInRoot(root *os.Root, name string, n int64) ([]byte, error) {
	f, _, err := openRegularInRoot(root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, n))
}

// openRegularInRoot opens name inside root without blocking, refuses
// anything but a regular file, then restores blocking reads.
func openRegularInRoot(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	f, err := openInRoot(root, name)
	if err != nil {
		return nil, nil, err
	}
	info, err := requireRegular(f)
	if err == nil {
		err = restoreBlocking(f)
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}
