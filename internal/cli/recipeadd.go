package cli

import (
	"fmt"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/recipe"
)

// runRecipeAdd installs the recipes of a pinned source from the operator's
// own clone of it (ADR 0028). creep makes no network call: the operator
// clones and checks out the commit with git, and creep checks that the
// clone is that commit of that repository before it copies anything.
func runRecipeAdd(e env, pinned, clone string) int {
	n, src, err := addRecipes(e, pinned, clone)
	if err != nil {
		printError(e.stderr, "creep recipe add", err)
		return exitcode.ConfigError
	}
	fmt.Fprintf(e.stdout, "recipe: installed %d recipe files from %s into ~/%s and pinned them in %s; each scan checks their checksums, then their fixtures with the model, before using them\n", n, src, recipeStore, recipe.LockFile)
	return exitcode.OK
}

// addRecipes checks the source, the policy and the clone, then installs.
func addRecipes(e env, pinned, clone string) (int, recipe.Source, error) {
	src, err := recipe.ParseSource(pinned)
	if err != nil {
		return 0, recipe.Source{}, err
	}
	resolved, err := loadConfig(e.opts)
	if err != nil {
		return 0, src, err
	}
	if patterns, enforced := resolved.PolicyRecipeSources(); !recipe.Allowed(src, patterns, enforced) {
		return 0, src, fmt.Errorf("%s: not in the %s recipe_sources allowlist", src.Repository(), policyEnv)
	}
	store := recipeFiles()
	files, err := store.ReadClone(clone, src)
	if err != nil {
		return 0, src, err
	}
	return len(files), src, store.Install(src, files)
}
