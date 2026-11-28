package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"runtime"

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
// tree it came with, as one git wrote over that tree does (#380): every
// entry has a mode git writes; every tracked regular file still on disk
// is a regular file with the executable bit git recorded (not compared on
// Windows, which has none), a recorded mtime, and the recorded size or a
// later mtime (an edit since git recorded it); and at least one tracked
// file on disk has the recorded size. Only an agreeing index proves vendor
// without bound; any other is bounded (boundVendor). An archive can still
// ship an index that agrees with its own tree, since it sets both sides.
// Past the scan deadline the index does not agree.
func indexMatchesTree(ctx context.Context, root *os.Root, entries []gitindex.Entry) bool {
	sameSize := false
	for i, e := range entries {
		if i%indexCheckEvery == 0 && ctx.Err() != nil {
			return false
		}
		ok, same := entryMatches(root, e)
		if !ok {
			return false
		}
		sameSize = sameSize || same
	}
	return sameSize
}

// entryMatches compares one entry with the tree; same says the file is on
// disk with the recorded size. A tracked path missing from disk (deleted,
// or outside a sparse checkout) agrees; any other stat error does not
// (fail closed).
func entryMatches(root *os.Root, e gitindex.Entry) (ok, same bool) {
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
	case err != nil || !info.Mode().IsRegular() || e.MtimeSec == 0 || !sameExecBit(e, info):
		return false, false
	}
	same = uint32(info.Size()) == e.Size //nolint:gosec // G115: git stores the size truncated to 32 bits
	return same || info.ModTime().Unix() > int64(e.MtimeSec), same
}

// sameExecBit compares the owner executable bit with the recorded mode.
func sameExecBit(e gitindex.Entry, info fs.FileInfo) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	return (info.Mode().Perm()&0o100 != 0) == (e.Mode == gitModeExec)
}
