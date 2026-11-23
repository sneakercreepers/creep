package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/recipe"
)

// cloneRecipes is the directory of a source's clone recipes are installed
// from: its *.json files, one level, no links.
const cloneRecipes = "recipes"

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
	files, err := readClone(clone, src)
	if err != nil {
		return 0, src, err
	}
	return len(files), src, installRecipes(src, files)
}

// readClone checks the clone (a detached HEAD at the pinned commit, origin
// at the source) and reads its recipe files, each one parsed.
func readClone(clone string, src recipe.Source) (map[string][]byte, error) {
	root, err := os.OpenRoot(clone)
	if err != nil {
		return nil, configError("clone", clone, err)
	}
	defer root.Close()
	if err := checkClone(root, src); err != nil {
		return nil, err
	}
	return readCloneRecipes(root)
}

// checkClone compares the clone's .git/HEAD and origin with src. A clone
// with a .git file (a worktree or submodule) is refused: creep reads only
// a .git directory, never a path a .git file points at.
func checkClone(root *os.Root, src recipe.Source) error {
	if err := requireDir(root, ".git"); err != nil {
		return err
	}
	head, err := readCappedFile(recipeOpener(root), "clone HEAD", filepath.Join(".git", "HEAD"), recipe.MaxHeadBytes)
	if err != nil {
		return err
	}
	if commit, ok := recipe.DetachedHead(head); !ok || commit != src.Commit {
		return fmt.Errorf("clone: HEAD is not detached at %s; run git checkout --detach %s in the clone", src.Commit, src.Commit)
	}
	cfg, err := readCappedFile(recipeOpener(root), "clone config", filepath.Join(".git", "config"), recipe.MaxGitConfigBytes)
	if err != nil {
		return err
	}
	if origin, ok := recipe.OriginRepository(cfg); !ok || origin != src.Repository() {
		return fmt.Errorf("clone: remote origin is not https://%s", src.Repository())
	}
	return nil
}

// requireDir refuses a name in root that is not a real directory.
func requireDir(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if err != nil {
		return configError("clone", name, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("clone: %s must be a directory, not a link or a file", name)
	}
	return nil
}

// readCloneRecipes reads every *.json file in the clone's recipes/
// directory: 1 to recipe.MaxSourceFiles of them, each with a name
// recipe.ValidFileName accepts, regular, and a valid recipe. Other files
// are ignored; a .json entry that breaks a rule fails the whole install.
func readCloneRecipes(root *os.Root) (map[string][]byte, error) {
	if err := requireDir(root, cloneRecipes); err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(root.FS(), cloneRecipes)
	if err != nil {
		return nil, configError("clone", cloneRecipes, err)
	}
	files := map[string][]byte{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if len(files) == recipe.MaxSourceFiles {
			return nil, fmt.Errorf("clone: more than %d recipe files in %s/", recipe.MaxSourceFiles, cloneRecipes)
		}
		data, err := readCloneRecipe(root, entry.Name())
		if err != nil {
			return nil, err
		}
		files[entry.Name()] = data
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("clone: no recipe files (*.json) in %s/", cloneRecipes)
	}
	return files, nil
}

// readCloneRecipe reads and parses one recipe file of the clone.
func readCloneRecipe(root *os.Root, name string) ([]byte, error) {
	if !recipe.ValidFileName(name) {
		return nil, fmt.Errorf("clone: %s/ holds a .json file whose name is not 1 to 59 a-z, 0-9, - and _ characters", cloneRecipes)
	}
	file := path.Join(cloneRecipes, name)
	data, err := readCappedFile(recipeOpener(root), "clone recipe", filepath.FromSlash(file), recipe.MaxFileBytes)
	if err != nil {
		return nil, err
	}
	if _, err := recipe.Parse(data, checkRecipePoC); err != nil {
		return nil, fmt.Errorf("clone recipe %s: %w", file, err)
	}
	return data, nil
}

// installRecipes writes the files under <owner>/<repo>/<commit>/ in the
// store, then the lock. A source's earlier install is replaced: its old
// commit directory is removed only after the new lock is written, so a
// failure leaves a lock whose files either all exist or fail the scan.
func installRecipes(src recipe.Source, files map[string][]byte) error {
	dir, ok := recipeStorePath()
	if !ok {
		return errors.New("recipe add: no home directory to install into")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return configError("recipe store", "~/"+recipeStore, err)
	}
	root, found, err := openRecipeStore()
	if err != nil || !found {
		return errors.Join(err, errors.New("recipe add: the recipe store could not be opened"))
	}
	defer root.Close()
	lock, err := readLock(root)
	if err != nil {
		return err
	}
	next, err := checkedLock(lock.Install(src, files))
	if err != nil {
		return err
	}
	if err := writeSourceFiles(root, src, files); err != nil {
		return err
	}
	if err := writeLock(root, next); err != nil {
		return err
	}
	return removeOldCommits(root, src)
}

// checkedLock marshals the lock and parses it back, so creep never writes
// a lock its own scan would refuse.
func checkedLock(l recipe.Lock) ([]byte, error) {
	data, err := l.Marshal()
	if err != nil {
		return nil, err
	}
	if _, err := recipe.ParseLock(data); err != nil {
		return nil, err
	}
	return data, nil
}
