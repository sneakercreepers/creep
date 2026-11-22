package recipe

import (
	_ "embed" // the starting recipe is data in template.json
	"slices"
)

//go:embed template.json
var template []byte

// Template is the recipe `creep recipe new` writes: a complete, valid
// recipe (TestTemplateParses) for the author to edit.
func Template() []byte { return slices.Clone(template) }
