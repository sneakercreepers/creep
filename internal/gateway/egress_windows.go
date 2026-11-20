//go:build windows

package gateway

import (
	"io/fs"
	"os"
	"syscall"
)

// extraOpenFlags is empty: Windows has no O_NOFOLLOW; the same-file check
// after open still catches a swapped log.
const extraOpenFlags = 0

// ownedBySelf is not checked on Windows; checkAccess skips it.
func ownedBySelf(fs.FileInfo) bool { return true }

// linkCount reads the hard-link count from the open handle: Go's Windows
// FileInfo does not carry it, and a second link would let another path,
// with its own ACL, alias the log.
func linkCount(f *os.File) (uint64, error) {
	var d syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &d); err != nil {
		return 0, err
	}
	return uint64(d.NumberOfLinks), nil
}

// syncDir is a no-op: Windows cannot flush a directory handle, and NTFS
// journals directory entries itself.
func syncDir(*os.File) error { return nil }
