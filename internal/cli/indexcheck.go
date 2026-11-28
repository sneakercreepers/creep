package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"

	"github.com/sneakercreepers/creep/internal/gitindex"
)

// The modes git writes into an index entry.
const (
	gitModeFile    = 0o100644
	gitModeExec    = 0o100755
	gitModeLink    = 0o120000
	gitModeGitlink = 0o160000
)

// indexCheckEvery is how many entries are compared between two looks at
// the scan deadline.
const indexCheckEvery = 256

// indexMatchesTree reports whether a git index agrees with the working
// tree it came with (#380): every entry has a mode git writes, every
// tracked regular file still on disk is a regular file whose size is the
// one git recorded or that changed after git recorded it (a newer mtime,
// as an edit leaves it), and at least one tracked regular file is on disk.
// An index that fails is not trusted, so nothing is vendor. A crafted
// index can still pass, since the archive sets both sides; the vendor
// bound (vendorbound.go) is what keeps such an index from hiding code
// behind exit 0. Past the scan deadline the index is not trusted.
func indexMatchesTree(ctx context.Context, root *os.Root, entries []gitindex.Entry) bool {
	present := false
	for i, e := range entries {
		if i%indexCheckEvery == 0 && ctx.Err() != nil {
			return false
		}
		ok, onDisk := entryMatches(root, e)
		if !ok {
			return false
		}
		present = present || onDisk
	}
	return present
}

// entryMatches compares one entry with the tree. A tracked path missing
// from disk (deleted, or outside a sparse checkout) holds no file and
// agrees; any other stat error disagrees (fail closed).
func entryMatches(root *os.Root, e gitindex.Entry) (ok, onDisk bool) {
	switch e.Mode {
	case gitModeLink, gitModeGitlink:
		// Windows checks links out as plain files (core.symlinks) and an
		// uninitialized submodule is an empty directory: nothing to compare.
		return true, false
	case gitModeFile, gitModeExec:
	default:
		return false, false
	}
	info, err := recoverStat(root.Lstat)(e.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true, false
	case err != nil || !info.Mode().IsRegular():
		return false, false
	}
	sameSize := uint32(info.Size()) == e.Size //nolint:gosec // G115: git stores the size truncated to 32 bits
	return sameSize || info.ModTime().Unix() > int64(e.MtimeSec), true
}
