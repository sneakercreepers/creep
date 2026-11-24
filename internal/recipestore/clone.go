package recipestore

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sneakercreepers/creep/internal/recipe"
)

// cloneRecipes is the directory of a source's clone recipes are installed
// from: its *.json files, one level, no links.
const cloneRecipes = "recipes"

// ReadClone checks the operator's clone (a detached HEAD at the pinned
// commit, origin at the source) and reads its recipe files, each one
// parsed. creep makes no network call: the operator clones and checks out
// the commit with git.
func (s Store) ReadClone(clone string, src recipe.Source) (map[string][]byte, error) {
	root, err := os.OpenRoot(clone)
	if err != nil {
		return nil, pathError("clone", clone, err)
	}
	defer root.Close()
	if err := s.checkClone(root, src); err != nil {
		return nil, err
	}
	return s.readCloneRecipes(root)
}

// checkClone compares the clone's .git/HEAD and origin with src. A clone
// with a .git file (a worktree or submodule) is refused: creep reads only
// a .git directory, never a path a .git file points at.
func (s Store) checkClone(root *os.Root, src recipe.Source) error {
	if err := requireDir(root, ".git"); err != nil {
		return err
	}
	head, err := s.Read(root, "clone HEAD", filepath.Join(".git", "HEAD"), recipe.MaxHeadBytes)
	if err != nil {
		return err
	}
	if commit, ok := recipe.DetachedHead(head); !ok || commit != src.Commit {
		return fmt.Errorf("clone: HEAD is not detached at %s; run git checkout --detach %s in the clone", src.Commit, src.Commit)
	}
	cfg, err := s.Read(root, "clone config", filepath.Join(".git", "config"), recipe.MaxGitConfigBytes)
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
		return pathError("clone", name, err)
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
func (s Store) readCloneRecipes(root *os.Root) (map[string][]byte, error) {
	if err := requireDir(root, cloneRecipes); err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(root.FS(), cloneRecipes)
	if err != nil {
		return nil, pathError("clone", cloneRecipes, err)
	}
	files := map[string][]byte{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if len(files) == recipe.MaxSourceFiles {
			return nil, fmt.Errorf("clone: more than %d recipe files in %s/", recipe.MaxSourceFiles, cloneRecipes)
		}
		data, err := s.readCloneRecipe(root, entry.Name())
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
func (s Store) readCloneRecipe(root *os.Root, name string) ([]byte, error) {
	if !recipe.ValidFileName(name) {
		return nil, fmt.Errorf("clone: %s/ holds a .json file whose name is not 1 to 59 a-z, 0-9, - and _ characters", cloneRecipes)
	}
	file := path.Join(cloneRecipes, name)
	data, err := s.Read(root, "clone recipe", filepath.FromSlash(file), recipe.MaxFileBytes)
	if err != nil {
		return nil, err
	}
	if _, err := recipe.Parse(data, s.PoC); err != nil {
		return nil, fmt.Errorf("clone recipe %s: %w", file, err)
	}
	return data, nil
}
