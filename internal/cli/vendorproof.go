package cli

import (
	"context"
	"os"
	"path"
	"strings"

	"github.com/sneakercreepers/creep/internal/gitindex"
	"github.com/sneakercreepers/creep/internal/repofile"
)

const (
	// gitIndexPath is the index of the repository at the scan root.
	gitIndexPath = ".git/index"
	// gitExcludePath holds the repository's own ignore patterns beside
	// its .gitignore files.
	gitExcludePath = ".git/info/exclude"
	// maxGitIgnoreBytes bounds one ignore file. A larger one is not read,
	// so it ignores nothing and its files are read (fail closed).
	maxGitIgnoreBytes = 256 << 10
)

// vendorProofs answers whether a file belongs to a tree the repository
// ignores and git does not track, so it may be listed as vendor without
// being read (#366). Both must hold:
//
//   - the repository's own ignore patterns (repofile.GitIgnore: the
//     .gitignore of each directory above the file, nearest first, then
//     .git/info/exclude) ignore the file or a directory above it; as in
//     git, a file under an ignored directory is ignored whatever a deeper
//     pattern says;
//   - git tracks nothing in the topmost ignored directory, or the file
//     itself, and nothing above it that could hold it (a submodule): an
//     install or a build output is never committed, and anything committed
//     is the author's code (#213). The check compares file identity, not
//     names (trackedIndex), so a tracked name that the file system
//     resolves into the tree counts.
//
// No directory, file or tool name is believed: a tree the repository does
// not ignore is read, whatever it is called. With no git index creep can
// read whole, nothing is proven, so every file is read like first-party
// code. Patterns are read once per directory and answers kept per tree.
type vendorProofs struct {
	ctx     context.Context // the scan deadline (#260)
	root    *os.Root
	tracked *trackedIndex
	loaded  bool
	indexOK bool
	off     bool // nothing is proven: a catch-all pattern or a fail-closed rewalk
	exclude repofile.GitIgnore
	rules   map[string]repofile.GitIgnore // by directory, "." is the root
	dirs    map[string]bool               // directory: ignored by its own patterns
	trees   map[string]bool               // topmost ignored entry: proven
}

// catchAllProbe is a name no real ignore pattern targets: patterns at the
// root that ignore it (such as *, /* or **) ignore the whole repository,
// so they prove nothing (#376 auditor M2).
const catchAllProbe = "creep-catch-all-probe-7f3a"

// noVendorProofs proves nothing, so every file is read.
func noVendorProofs(ctx context.Context, root *os.Root) *vendorProofs {
	v := newVendorProofs(ctx, root)
	v.loaded, v.off = true, true
	return v
}

func newVendorProofs(ctx context.Context, root *os.Root) *vendorProofs {
	return &vendorProofs{
		ctx: ctx, root: root,
		rules: map[string]repofile.GitIgnore{}, dirs: map[string]bool{}, trees: map[string]bool{},
	}
}

// proven reports whether rel is in an ignored, untracked tree. Past the
// scan deadline nothing is proven: reading the index and the ignore files
// and comparing a tree's identity read and stat the repository, which the
// deadline ends, so a file is then read or listed like first-party code
// (fail closed).
func (v *vendorProofs) proven(rel string) bool {
	if v.ctx.Err() != nil {
		return false
	}
	if !v.loaded {
		v.loaded = true
		v.tracked, v.indexOK = readTracked(v.root)
		v.exclude = v.readIgnore(".", gitExcludePath)
		v.off = v.ignores(catchAllProbe, true) || v.ignores(catchAllProbe, false)
	}
	if v.off || !v.indexOK || v.tracked.folded.touches(rel) {
		return false
	}
	tree, ok := v.ignoredTree(rel)
	if !ok {
		return false
	}
	found, done := v.trees[tree]
	if !done {
		found = v.installed(tree)
		v.trees[tree] = found
	}
	return found
}

// ignoredTree returns the topmost directory above rel that the patterns
// ignore, or rel itself when only a pattern for the file does.
func (v *vendorProofs) ignoredTree(rel string) (string, bool) {
	for i := 0; i < len(rel); i++ {
		if rel[i] != '/' {
			continue
		}
		dir := rel[:i]
		ignored, done := v.dirs[dir]
		if !done {
			ignored = v.ignores(dir, true)
			v.dirs[dir] = ignored
		}
		if ignored {
			return dir, true
		}
	}
	return rel, v.ignores(rel, false)
}

// ignores applies git's precedence to rel, whose directories above are not
// ignored: the nearest .gitignore with a matching pattern decides, then
// info/exclude.
func (v *vendorProofs) ignores(rel string, dir bool) bool {
	for d := parentDir(rel); ; d = parentDir(d) {
		if matched, ignored := v.rulesIn(d).Match(rel, dir); matched {
			return ignored
		}
		if d == "." {
			break
		}
	}
	matched, ignored := v.exclude.Match(rel, dir)
	return matched && ignored
}

// rulesIn returns the patterns of dir's .gitignore, read once.
func (v *vendorProofs) rulesIn(dir string) repofile.GitIgnore {
	g, done := v.rules[dir]
	if !done {
		g = v.readIgnore(dir, path.Join(dir, ".gitignore"))
		v.rules[dir] = g
	}
	return g
}

// readIgnore parses the ignore file at name for patterns under base; a
// missing, irregular or oversized file has none.
func (v *vendorProofs) readIgnore(base, name string) repofile.GitIgnore {
	data, err := readInRoot(v.root, name, maxGitIgnoreBytes)
	if err != nil {
		data = nil
	}
	return repofile.ParseGitIgnore(base, data)
}

// installed reports whether git provably tracks nothing in tree. A tree
// whose path is not ASCII never is: a cheap guard beside the identity
// check, as git and the file system may spell such names in different
// Unicode forms (macOS).
func (v *vendorProofs) installed(tree string) bool {
	return isASCII(tree) && !v.tracked.tracks(v.root, tree)
}

// readTracked reads the paths the repository's git index tracks; ok is
// false when there is no index or it cannot be read whole.
func readTracked(root *os.Root) (*trackedIndex, bool) {
	data, err := readInRoot(root, gitIndexPath, gitindex.MaxBytes)
	if err != nil {
		return nil, false
	}
	paths, err := gitindex.Parse(data)
	if err != nil {
		return nil, false
	}
	return newTrackedIndex(paths), true
}

func isASCII(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r >= 0x80 })
}
