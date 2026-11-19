package cli

import (
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
)

// trackedIndex answers whether git tracks anything in a directory of the
// scanned tree. A path in the index is a name, and the file system may
// resolve another name to the same directory: an NTFS 8.3 short name
// (node_m~1), another case on Windows or macOS, NTFS trailing dots and
// spaces, or another Unicode form on macOS (#267 tester H1). So names are
// only a first guard (folded), and the answer comes from file identity: a
// tracked path whose directory at the tree's depth is the tree itself
// tracks the tree.
type trackedIndex struct {
	folded  trackedPaths
	nodes   map[int][]string // tracked entries and their directories, by depth
	entries map[int][]string // tracked entries only, by depth
	stats   map[string]statResult
}

type statResult struct {
	info fs.FileInfo
	err  error
}

func newTrackedIndex(paths []string) *trackedIndex {
	t := &trackedIndex{folded: newTrackedPaths(paths), nodes: map[int][]string{}, entries: map[int][]string{}, stats: map[string]statResult{}}
	seen := map[string]bool{}
	for _, p := range paths {
		t.entries[pathDepth(p)] = append(t.entries[pathDepth(p)], p)
		for n := p; n != "." && !seen[n]; n = parentDir(n) {
			seen[n] = true
			t.nodes[pathDepth(n)] = append(t.nodes[pathDepth(n)], n)
		}
	}
	return t
}

// tracks reports whether git tracks dir, anything under it, or an entry
// above it (a submodule, whose own commits may hold dir). Anything it
// cannot resolve counts as tracked; a tracked path that does not exist on
// disk holds no file, so it does not count.
func (t *trackedIndex) tracks(root *os.Root, dir string) bool {
	if t.folded.touches(dir) {
		return true
	}
	info, err := root.Lstat(dir)
	if err != nil || t.sameAsAny(root, info, t.nodes[pathDepth(dir)]) {
		return true
	}
	for a := parentDir(dir); a != "."; a = parentDir(a) {
		info, err := root.Lstat(a)
		if err != nil || t.sameAsAny(root, info, t.entries[pathDepth(a)]) {
			return true
		}
	}
	return false
}

// sameAsAny reports whether one of names resolves to target, or cannot be
// resolved for any reason but its absence. Every alias of a name keeps its
// depth, so only names at target's depth are compared.
func (t *trackedIndex) sameAsAny(root *os.Root, target fs.FileInfo, names []string) bool {
	for _, n := range names {
		r, ok := t.stats[n]
		if !ok {
			r.info, r.err = root.Lstat(n)
			t.stats[n] = r
		}
		switch {
		case errors.Is(r.err, fs.ErrNotExist):
		case r.err != nil, os.SameFile(r.info, target):
			return true
		}
	}
	return false
}

func pathDepth(p string) int { return strings.Count(p, "/") + 1 }

func parentDir(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return "."
	}
	return p[:i]
}

// trackedPaths is the sorted list of tracked paths, folded (foldPath). It
// is the cheap guard before the identity check: folding only makes more
// trees count as tracked.
type trackedPaths []string

func newTrackedPaths(paths []string) trackedPaths {
	t := make(trackedPaths, len(paths))
	for i, p := range paths {
		t[i] = foldPath(p)
	}
	slices.Sort(t)
	return t
}

// foldPath lowercases a path and drops the trailing dots and spaces of
// each segment, as NTFS does when it resolves a name.
func foldPath(p string) string {
	segs := strings.Split(strings.ToLower(p), "/")
	for i, s := range segs {
		segs[i] = strings.TrimRight(s, ". ")
	}
	return strings.Join(segs, "/")
}

// touches reports whether a folded tracked path is dir itself (a gitlink,
// a link or a file), lies under it, or lies above it. A path above it can
// only be a gitlink or a link: a submodule's own commits may hold the tree.
func (t trackedPaths) touches(dir string) bool {
	dir = foldPath(dir)
	if i, ok := slices.BinarySearch(t, dir+"/"); ok || i < len(t) && strings.HasPrefix(t[i], dir+"/") {
		return true
	}
	for p := dir; p != "."; p = parentDir(p) {
		if _, ok := slices.BinarySearch(t, p); ok {
			return true
		}
	}
	return false
}
