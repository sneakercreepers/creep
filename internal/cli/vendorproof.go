package cli

import (
	"io/fs"
	"os"
	"path"

	"github.com/sneakercreepers/creep/internal/gitindex"
	"github.com/sneakercreepers/creep/internal/repofile"
)

// gitIndexPath is the index of the repository at the scan root.
const gitIndexPath = ".git/index"

// vendorProofs answers whether a file under a vendor-named directory belongs
// to an installed dependency tree, so it may be listed as vendor without
// being read. Both must hold:
//
//   - its package manager's mark (repofile.VendorEvidence) is a regular file
//     in the repository with exactly that name;
//   - git tracks nothing in the tree, and nothing above it that could hold
//     it (a submodule): a package manager's install is never committed, and
//     anything committed is the author's code, mark included (#213). The
//     check compares file identity, not names (trackedIndex), so a tracked
//     name that the file system resolves into the tree counts.
//
// With no git index creep can read whole, no tree is proven, so every
// vendor file is read like first-party code. Answers are kept per mark, so
// a large node_modules costs one directory read per package, and the index
// is read once, on the first vendor file.
type vendorProofs struct {
	root    *os.Root
	seen    map[string]bool
	tracked *trackedIndex
	loaded  bool
	indexOK bool
}

func newVendorProofs(root *os.Root) *vendorProofs {
	return &vendorProofs{root: root, seen: map[string]bool{}}
}

func (v *vendorProofs) proven(rel string) bool {
	mark, ok := repofile.VendorEvidence(rel)
	if !ok {
		return false
	}
	if found, done := v.seen[mark]; done {
		return found
	}
	found := v.installed(path.Dir(mark)) && hasRegularEntry(v.root, mark)
	v.seen[mark] = found
	return found
}

// installed reports whether git provably tracks nothing in tree. A tree
// whose path is not ASCII never is: a cheap guard beside the identity
// check, as git and the file system may spell such names in different
// Unicode forms (macOS).
func (v *vendorProofs) installed(tree string) bool {
	if !isASCII(tree) {
		return false
	}
	if !v.loaded {
		v.loaded = true
		v.tracked, v.indexOK = readTracked(v.root)
	}
	return v.indexOK && !v.tracked.tracks(v.root, tree)
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

// hasRegularEntry reports whether name's directory lists an entry spelled
// byte for byte like name that is a regular file. A stat would not do: on a
// case-insensitive file system (Windows, macOS) it finds PACKAGE.JSON for
// package.json (#213 tester L1).
func hasRegularEntry(root *os.Root, name string) bool {
	entries, err := fs.ReadDir(root.FS(), path.Dir(name))
	if err != nil {
		return false
	}
	base := path.Base(name)
	for _, e := range entries {
		if e.Name() == base {
			return e.Type().IsRegular()
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
