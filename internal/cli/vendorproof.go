package cli

import (
	"io/fs"
	"os"
	"path"

	"github.com/sneakercreepers/creep/internal/static"
)

// vendorProofs answers whether a file under a vendor-named directory belongs
// to a dependency tree: only when the mark its package manager leaves
// (static.VendorEvidence) is a regular file in the repository with exactly
// that name. A proven file may be listed as vendor without parsing only when
// it cannot hold a route (addRepoFile). Answers are kept per mark, so a large
// node_modules costs one directory read per package.
type vendorProofs struct {
	root *os.Root
	seen map[string]bool
}

func newVendorProofs(root *os.Root) *vendorProofs {
	return &vendorProofs{root: root, seen: map[string]bool{}}
}

func (v *vendorProofs) proven(rel string) bool {
	mark, ok := static.VendorEvidence(rel)
	if !ok {
		return false
	}
	if found, done := v.seen[mark]; done {
		return found
	}
	found := hasRegularEntry(v.root, mark)
	v.seen[mark] = found
	return found
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
