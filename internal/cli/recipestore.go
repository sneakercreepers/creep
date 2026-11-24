package cli

import (
	"os"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/recipestore"
)

// recipeStore is the store directory as messages show it, under "~/".
const recipeStore = recipestore.Dir

// installedRecipe is one verified lock entry (recipestore.Installed).
type installedRecipe = recipestore.Installed

// recipeFiles is the store with cli's file rules: every read goes through
// recipeOpener (regular, singly linked, opened without blocking, capped)
// and every PoC meets checkRecipePoC.
func recipeFiles() recipestore.Store {
	return recipestore.Store{Read: readStoreFile, PoC: checkRecipePoC}
}

func readStoreFile(root *os.Root, label, name string, limit int64) ([]byte, error) {
	return readCappedFile(recipeOpener(root), label, name, limit)
}

// loadInstalledRecipes verifies every installed recipe before a scan opens
// anything, under the org policy's recipe_sources only; any fault fails
// the scan closed (exit 2).
func loadInstalledRecipes(r *config.Resolved) ([]installedRecipe, error) {
	patterns, enforced := r.PolicyRecipeSources()
	return recipeFiles().Load(recipestore.Policy{Patterns: patterns, Enforced: enforced})
}
