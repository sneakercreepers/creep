package recipe

import (
	"path"
	"slices"
	"strings"

	"github.com/sneakercreepers/creep/internal/reader"
)

// HintFor returns the hint of the first recipe, in the order given (the
// lock's), whose class is class and whose applies_to lists the extension
// of file, or "" when none does. The hint goes only to reader.Target.Hint.
func HintFor(recipes []*Recipe, class reader.Class, file string) string {
	ext := strings.ToLower(path.Ext(file))
	for _, r := range recipes {
		if classes[r.Class] == class && slices.Contains(r.AppliesTo, ext) {
			return r.Hint
		}
	}
	return ""
}
