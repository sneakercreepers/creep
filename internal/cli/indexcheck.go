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

const (
	// indexCheckEvery is how many entries are compared between two looks
	// at the scan deadline.
	indexCheckEvery = 256
	// mtimeFloor is 2000-01-01 UTC. git records the file's own mtime when
	// it stages it; a file dated earlier (an archive that keeps 1970
	// times, a build that pins SOURCE_DATE_EPOCH) makes the index
	// disagree. That fails safe: the index is only bounded, never believed
	// less than no index.
	mtimeFloor = 946_684_800
	// missingShare bounds the tracked regular files that may be missing
	// from disk: one, or one in missingShare, whichever is more. A
	// checkout with a few uncommitted deletions agrees; an index of mostly
	// absent files beside one decoy does not.
	missingShare = 20
)

// entryState is how one index entry compares with the tree.
type entryState uint8

const (
	entryDisagrees entryState = iota
	entryAgrees               // agrees, but proves nothing alone (an edit since, a link, a gitlink)
	entryExact                // on disk with the recorded size
	entryMissing              // tracked but not on disk (deleted, or outside a sparse checkout)
)

// indexMatchesTree reports whether a git index agrees with the working
// tree it came with, as one git wrote over that tree does (#380): every
// entry has a mode git writes; every tracked regular file has a recorded
// mtime after mtimeFloor; each one on disk is a regular file with the
// executable bit git recorded (not compared on Windows, which has none)
// and the recorded size or a later mtime (an edit since git recorded it);
// at most one, or one in missingShare, is missing from disk; and at least
// one is on disk with the recorded size. Only an agreeing index proves
// vendor without bound; any other is bounded (boundVendor). An archive can
// still ship an index that agrees with its own tree, since it sets both
// sides. Past the scan deadline the index does not agree.
//
// Edges that make a real index disagree, all failing safe (the vendor it
// proves is bounded, never hidden without bound): a file older than
// mtimeFloor; many uncommitted deletions or a sparse checkout with most
// files absent; a file whose executable bit was changed outside git
// (core.fileMode false on Unix); a file replaced by a directory; an index
// whose every tracked file was edited since it was written. Cost:
// one Lstat per entry (BenchmarkIndexMatchesTree).
func indexMatchesTree(ctx context.Context, root *os.Root, entries []gitindex.Entry) bool {
	var exact, missing, regular int
	for i, e := range entries {
		if i%indexCheckEvery == 0 && ctx.Err() != nil {
			return false
		}
		switch entryMatches(root, e) {
		case entryDisagrees:
			return false
		case entryExact:
			exact++
		case entryMissing:
			missing++
		}
		if e.Mode == gitModeFile || e.Mode == gitModeExec {
			regular++
		}
	}
	return exact > 0 && missing <= max(1, regular/missingShare)
}

// entryMatches compares one entry with the tree. A stat error other than
// a missing file disagrees (fail closed).
func entryMatches(root *os.Root, e gitindex.Entry) entryState {
	switch e.Mode {
	case gitModeLink, gitModeGitlink:
		// Windows checks links out as plain files (core.symlinks) and an
		// uninitialized submodule is an empty directory: nothing to compare.
		return entryAgrees
	case gitModeFile, gitModeExec:
	default:
		return entryDisagrees
	}
	if e.MtimeSec < mtimeFloor {
		return entryDisagrees
	}
	info, err := recoverStat(root.Lstat)(e.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return entryMissing
	case err != nil || !info.Mode().IsRegular() || !sameExecBit(e, info):
		return entryDisagrees
	case uint32(info.Size()) == e.Size: //nolint:gosec // G115: git stores the size truncated to 32 bits
		return entryExact
	case info.ModTime().Unix() > int64(e.MtimeSec):
		return entryAgrees
	}
	return entryDisagrees
}

// sameExecBit compares the owner executable bit with the recorded mode.
func sameExecBit(e gitindex.Entry, info fs.FileInfo) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	return (info.Mode().Perm()&0o100 != 0) == (e.Mode == gitModeExec)
}
