package cli

import (
	"os"

	"github.com/sneakercreepers/creep/internal/static"
)

// vendorProofs answers whether a file under a vendor-named directory may be
// listed as vendor without being read: only when the mark its package
// manager leaves (static.VendorEvidence) is a regular file in the
// repository. Answers are kept per mark, so a large node_modules costs one
// Lstat per package.
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
	info, err := v.root.Lstat(mark)
	found := err == nil && info.Mode().IsRegular()
	v.seen[mark] = found
	return found
}
