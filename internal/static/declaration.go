package static

import (
	"fmt"
	"strings"
)

// declarationSuffixes name TypeScript declaration files, compared without
// case.
var declarationSuffixes = []string{".d.ts", ".d.mts", ".d.cts"}

// IsDeclaration reports whether name is a TypeScript declaration file.
func IsDeclaration(name string) bool {
	lower := strings.ToLower(name)
	for _, s := range declarationSuffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	return false
}

// AddDeclaration is AddJavaScript for a declaration file of a proven
// dependency tree (VendorEvidence): a route-free file under a vendor path is
// listed as vendor even when its parse has errors. The pinned grammar lags
// TypeScript's type syntax (template literal types in router's route.d.ts
// do not parse, #255 tester M3), and real packages ship hundreds of such
// files. The file is still parsed and extracted, so a route the extractor
// finds, even in a tree with errors, is evaluated like first-party code.
// Residual: a route inside a region the grammar could not read goes unseen,
// where a first-party file would make the run incomplete; a declaration
// file runs only when code imports it by name. Any other file is refused.
func (e *Extractor) AddDeclaration(path string, tree *Tree, src []byte) error {
	if !IsDeclaration(path) {
		return fmt.Errorf("extract %s: not a declaration file", path)
	}
	if tree != nil && tree.Language != TypeScript {
		return fmt.Errorf("extract %s: %s tree is not typescript", path, tree.Language)
	}
	return e.addSource(path, tree, src, extractJavaScript, true)
}
