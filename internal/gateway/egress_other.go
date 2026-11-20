//go:build !unix && !windows

package gateway

import (
	"io/fs"
	"os"
)

// extraOpenFlags is empty: these platforms have no O_NOFOLLOW; the
// same-file check after open still catches a swapped log.
const extraOpenFlags = 0

// ownedBySelf is not checked off Unix and Windows.
func ownedBySelf(fs.FileInfo) bool { return true }

// linkCount is not checked off Unix and Windows.
func linkCount(*os.File) (uint64, error) { return 1, nil }

// syncDir is a no-op off Unix.
func syncDir(*os.File) error { return nil }
