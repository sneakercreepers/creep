package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// errRootPanic marks an os.Root call that panicked. Go 1.27.4's os.Root
// panics on Windows when it follows some relative links in a subdirectory,
// such as real/web -> ..\real (index out of range in os.doInRoot,
// os/root_openat.go; no Go issue found on 2026-11-20). The repository
// chooses its links, so a crafted one must not crash the scan: the caller
// gets an error and treats the name as unresolvable (fail closed).
var errRootPanic = errors.New("os.Root panicked")

// recoverStat wraps a stat function of an os.Root (Stat or Lstat) so that
// a panic inside it is returned as errRootPanic.
func recoverStat(stat func(string) (fs.FileInfo, error)) func(string) (fs.FileInfo, error) {
	return func(name string) (info fs.FileInfo, err error) {
		defer func() {
			if p := recover(); p != nil {
				info, err = nil, fmt.Errorf("stat %q: %w: %v", name, errRootPanic, p)
			}
		}()
		return stat(name)
	}
}

// readlinkInRoot reads the target of the link at name, never following
// it, with a panic returned as errRootPanic.
func readlinkInRoot(root *os.Root, name string) (target string, err error) {
	defer func() {
		if p := recover(); p != nil {
			target, err = "", fmt.Errorf("readlink %q: %w: %v", name, errRootPanic, p)
		}
	}()
	return root.Readlink(name)
}
