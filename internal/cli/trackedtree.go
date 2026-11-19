package cli

import (
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
)

// maxTrackedSiblings bounds the tracked names compared with one directory.
// A directory with more tracked names beside its aliases counts as tracked
// (fail closed), so the identity check costs at most this many comparisons
// per installed tree and per directory above one.
const maxTrackedSiblings = 4096

// trackedIndex answers whether git tracks anything in a directory of the
// scanned tree. A path in the index is a name, and the file system may
// resolve another name to the same directory: an NTFS 8.3 short name
// (node_m~1), another case on Windows or macOS, NTFS trailing dots and
// spaces, or another Unicode form on macOS (#267 tester H1). So names are
// only a first guard (folded), and the answer comes from file identity.
//
// An alias resolves component by component, so a tracked name aliases a
// directory only when its parent name aliases the directory's parent. The
// check walks down from the root that way and compares a directory only
// with the tracked names under its parent's aliases. Worst case: each
// tracked name is resolved at most once per kind of lookup, and the
// comparisons are at most maxTrackedSiblings per installed tree and per
// distinct directory above one (BenchmarkTrackedIndexTracks).
type trackedIndex struct {
	folded    trackedPaths
	children  map[string][]string // tracked entries and their directories, by parent ("." is the root)
	entries   map[string][]string // tracked entries only, by parent
	lstats    map[string]statResult
	stats     map[string]statResult
	aliases   map[string]aliasResult
	submodule map[string]bool // directories above a tree: does a tracked entry resolve to one
}

type statResult struct {
	info fs.FileInfo
	err  error
}

// aliasResult holds the tracked names that resolve to a directory; ok is
// false when that cannot be told.
type aliasResult struct {
	names []string
	ok    bool
}

func newTrackedIndex(paths []string) *trackedIndex {
	t := &trackedIndex{
		folded: newTrackedPaths(paths), children: map[string][]string{}, entries: map[string][]string{},
		lstats: map[string]statResult{}, stats: map[string]statResult{}, aliases: map[string]aliasResult{}, submodule: map[string]bool{},
	}
	seen := map[string]bool{}
	for _, p := range paths {
		t.entries[parentDir(p)] = append(t.entries[parentDir(p)], p)
		for n := p; n != "." && !seen[n]; n = parentDir(n) {
			seen[n] = true
			t.children[parentDir(n)] = append(t.children[parentDir(n)], n)
		}
	}
	return t
}

// tracks reports whether git tracks dir, anything under it, or an entry
// above it (a submodule, whose own commits may hold dir). Anything it
// cannot resolve counts as tracked; a tracked path that does not exist on
// disk holds no file, so it does not count.
func (t *trackedIndex) tracks(root *os.Root, dir string) bool {
	if t.folded.touches(dir) || t.resolvesTo(root, dir, t.children) {
		return true
	}
	for a := parentDir(dir); a != "."; a = parentDir(a) {
		hit, done := t.submodule[a]
		if !done {
			hit = t.resolvesTo(root, a, t.entries)
			t.submodule[a] = hit
		}
		if hit {
			return true
		}
	}
	return false
}

// resolvesTo reports whether a tracked name in byParent, under an alias of
// dir's parent, resolves to dir, or whether that cannot be told.
func (t *trackedIndex) resolvesTo(root *os.Root, dir string, byParent map[string][]string) bool {
	target, err := root.Lstat(dir)
	if err != nil {
		return true
	}
	parents, ok := t.aliasesOf(root, parentDir(dir))
	names := namesUnder(parents, byParent)
	if !ok || len(names) > maxTrackedSiblings {
		return true
	}
	for _, n := range names {
		r := cachedStat(t.lstats, root.Lstat, n)
		switch {
		case errors.Is(r.err, fs.ErrNotExist):
		case r.err != nil, os.SameFile(r.info, target):
			return true
		}
	}
	return false
}

// aliasesOf returns the tracked directory names that resolve to dir,
// following links as a path component does; "." is the root itself.
func (t *trackedIndex) aliasesOf(root *os.Root, dir string) ([]string, bool) {
	if dir == "." {
		return []string{"."}, true
	}
	r, done := t.aliases[dir]
	if !done {
		r = t.findAliases(root, dir)
		t.aliases[dir] = r
	}
	return r.names, r.ok
}

func (t *trackedIndex) findAliases(root *os.Root, dir string) aliasResult {
	target, err := root.Stat(dir)
	if err != nil {
		return aliasResult{}
	}
	parents, ok := t.aliasesOf(root, parentDir(dir))
	names := namesUnder(parents, t.children)
	if !ok || len(names) > maxTrackedSiblings {
		return aliasResult{}
	}
	out := []string{}
	for _, n := range names {
		r := cachedStat(t.stats, root.Stat, n)
		switch {
		case errors.Is(r.err, fs.ErrNotExist):
		case r.err != nil:
			return aliasResult{}
		case os.SameFile(r.info, target):
			out = append(out, n)
		}
	}
	return aliasResult{names: out, ok: true}
}

func namesUnder(parents []string, byParent map[string][]string) []string {
	var names []string
	for _, p := range parents {
		names = append(names, byParent[p]...)
	}
	return names
}

func cachedStat(cache map[string]statResult, stat func(string) (fs.FileInfo, error), name string) statResult {
	r, ok := cache[name]
	if !ok {
		r.info, r.err = stat(name)
		cache[name] = r
	}
	return r
}

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
