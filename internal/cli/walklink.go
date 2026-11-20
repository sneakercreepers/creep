package cli

import (
	"context"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/report"
)

// maxLinkSteps bounds the names of a link's target that are followed; a
// longer target is listed (fail closed), so a link costs at most this many
// map lookups and one readlink.
const maxLinkSteps = 256

// walkedTree is every directory and regular file the walk reached at its
// own path, by parent and name. A link's target is followed over these
// names only, never by the file system: os.Root.Stat on a link panics in
// Go 1.27.4 on Windows for some relative targets (index out of range in
// os.doInRoot; no Go issue found on 2026-11-20), and climbing a target
// with Stat cost O(depth²) per link (#214 tester H1, M2).
type walkedTree struct {
	ids      map[string]int
	parents  []int
	dirs     []bool
	children map[childKey]int
}

type childKey struct {
	parent int
	name   string
}

func newWalkedTree() *walkedTree {
	return &walkedTree{ids: map[string]int{".": 0}, parents: []int{-1}, dirs: []bool{true}, children: map[childKey]int{}}
}

// add records rel, which the walk reached through directories it reached.
func (w *walkedTree) add(rel string, dir bool) {
	parent, ok := w.ids[path.Dir(rel)]
	if !ok || rel == "." {
		return
	}
	id := len(w.parents)
	w.ids[rel] = id
	w.parents = append(w.parents, parent)
	w.dirs = append(w.dirs, dir)
	w.children[childKey{parent, path.Base(rel)}] = id
}

// reaches reports whether target, read from the link at rel, names an
// entry the walk reached at its own path. Each step stays on walked
// entries: ".." leaves a walked directory for its parent, any other name
// must be a walked child, so no step passes through a link and the result
// is what the file system resolves. An empty or absolute target, one that
// leaves the root, names a link, the root's .git or .creep (never walked)
// or anything else the walk did not reach, is not reached.
func (w *walkedTree) reaches(rel, target string) bool {
	slashed := filepath.ToSlash(target)
	if target == "" || filepath.IsAbs(target) || filepath.VolumeName(target) != "" || strings.HasPrefix(slashed, "/") {
		return false
	}
	names := strings.Split(slashed, "/")
	cur, ok := w.ids[path.Dir(rel)]
	if !ok || len(names) > maxLinkSteps {
		return false
	}
	for _, name := range names {
		if cur, ok = w.step(cur, name); !ok {
			return false
		}
	}
	return true
}

// step moves from the walked directory cur by one name of a link target.
func (w *walkedTree) step(cur int, name string) (int, bool) {
	if !w.dirs[cur] {
		return 0, false
	}
	switch name {
	case "", ".":
		return cur, true
	case "..":
		return w.parents[cur], cur != 0
	}
	next, ok := w.children[childKey{cur, name}]
	return next, ok
}

// pendingLink is a link or special file whose gap waits for the end of
// the walk, when every entry its target could name has been reached.
type pendingLink struct {
	gap  int // index in repoFiles.gaps
	rel  string
	mode fs.FileMode
}

// resolveLinks fills each pending gap (linkGap) and drops those not
// listed, keeping the walk's order.
func resolveLinks(ctx context.Context, root *os.Root, files *repoFiles, links []pendingLink, tree *walkedTree, proofs *vendorProofs) {
	if len(links) == 0 {
		return
	}
	for _, l := range links {
		files.gaps[l.gap].Reason = linkGap(ctx, root, l, tree, proofs)
	}
	kept := files.gaps[:0]
	for _, g := range files.gaps {
		if g.Reason != "" {
			kept = append(kept, g)
		}
	}
	files.gaps = kept
}

// linkGap lists a link or special file the walk does not follow when it
// could hold source: its name is a source name, or it may be a directory
// the walk does not reach at its own path (unreached), whatever its name
// (#214). One in an installed tree is vendor, like the tree's files; any
// other is not_regular, which makes the run incomplete (ADR 0009).
func linkGap(ctx context.Context, root *os.Root, l pendingLink, tree *walkedTree, proofs *vendorProofs) report.SkipReason {
	if !discover.SourceName(l.rel) && !unreached(ctx, root, l, tree) {
		return ""
	}
	if report.ValidPath(l.rel) && proofs.proven(l.rel) {
		return report.SkipVendor
	}
	return report.SkipNotRegular
}

// unreached reports whether the entry may be a directory the walk does not
// cover. A FIFO, socket or device is not a directory. Past the scan
// deadline (#260) nothing is read and anything else may be one (fail
// closed). A symbolic link is covered when its target, read with one
// readlink, names an entry the walk reached (walkedTree.reaches). Any
// other entry (a Windows junction, a OneDrive placeholder or another
// reparse point, all ModeIrregular) is told apart by mayBeDirectory.
func unreached(ctx context.Context, root *os.Root, l pendingLink, tree *walkedTree) bool {
	if l.mode&(fs.ModeNamedPipe|fs.ModeSocket|fs.ModeDevice|fs.ModeCharDevice) != 0 {
		return false
	}
	if ctx.Err() != nil {
		return true
	}
	if l.mode&fs.ModeSymlink == 0 {
		return mayBeDirectory(recoverStat(root.Stat), l.rel)
	}
	target, err := readlinkInRoot(root, l.rel)
	return err != nil || !tree.reaches(l.rel, target)
}

// mayBeDirectory reports whether a reparse point that is not a symbolic
// link may be a directory. A junction is refused by the root (its target
// is absolute), so it counts as one; a OneDrive placeholder stats as the
// regular file it stands for and keeps the rule for files (listed only
// when named as source). Stat's panic is recovered (recoverStat).
func mayBeDirectory(stat func(string) (fs.FileInfo, error), rel string) bool {
	info, err := stat(rel)
	return err != nil || info.IsDir()
}
