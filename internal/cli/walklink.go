package cli

import (
	"io/fs"
	"os"
	"slices"

	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/report"
)

// maxLinkClimb bounds the climb from a link's target up to the root; a
// deeper target counts as not walked (fail closed).
const maxLinkClimb = 256

// linkGap lists a link or special file the walk does not follow when it
// could hold source: its name is a source name, or it may be a directory
// the walk does not reach at its own path (unwalkedDirectory), whatever
// its name (#214). One in an installed tree is vendor, like the tree's
// files; any other is not_regular, which makes the run incomplete
// (ADR 0009).
func linkGap(root *os.Root, rel string, proofs *vendorProofs) report.SkipReason {
	if !discover.SourceName(rel) && !unwalkedDirectory(root, rel) {
		return ""
	}
	if report.ValidPath(rel) && proofs.proven(rel) {
		return report.SkipVendor
	}
	return report.SkipNotRegular
}

// unwalkedDirectory reports whether the entry at rel may be a directory
// the walk does not cover. The root never leaves the repository, so a link
// whose target is outside it, missing, a loop or an absolute path, and a
// Windows junction, all of which the root refuses, cannot be told from a
// directory without following it out; each counts as one (fail closed). A
// link the root resolves to a directory is covered unless that directory
// lies under the root's .git or .creep (walkReaches). Only metadata is
// read, never the target's contents.
func unwalkedDirectory(root *os.Root, rel string) bool {
	info, err := root.Stat(rel)
	if err != nil {
		return true
	}
	return info.IsDir() && !walkReaches(root, rel)
}

// walkReaches reports whether the directory rel resolves to is walked at
// its own path: climbing from it with "..", which the root resolves on the
// real directory rather than on the name, meets the root before any of
// skipDirs. Every directory in the repository is walked except those.
func walkReaches(root *os.Root, rel string) bool {
	top, err := root.Stat(".")
	if err != nil {
		return false
	}
	skipped := skippedDirInfos(root)
	dir := rel
	for range maxLinkClimb {
		info, err := root.Stat(dir)
		if err != nil || slices.ContainsFunc(skipped, func(s fs.FileInfo) bool { return os.SameFile(info, s) }) {
			return false
		}
		if os.SameFile(info, top) {
			return true
		}
		dir += "/.."
	}
	return false
}

// skippedDirInfos is each of skipDirs that is a real directory at the root.
func skippedDirInfos(root *os.Root) []fs.FileInfo {
	var infos []fs.FileInfo
	for name := range skipDirs {
		if info, err := root.Lstat(name); err == nil && info.IsDir() {
			infos = append(infos, info)
		}
	}
	return infos
}
