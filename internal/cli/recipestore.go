package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/recipe"
)

// recipeStore is where `creep recipe add` installs recipes and creep.lock
// (ADR 0028): the operator's home, next to the user config, never the
// scanned repository. It is shown as "~/..." in messages.
const recipeStore = ".creep/recipes"

// installedRecipe is one lock entry whose file matched its checksum and
// parsed: bytes for recipe.Checker.Load, which alone makes it usable.
type installedRecipe struct {
	pin  recipe.Pin
	data []byte
}

// recipeStorePath is ~/.creep/recipes, or false with no home directory.
func recipeStorePath() (string, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	return filepath.Join(home, filepath.FromSlash(recipeStore)), true
}

// openRecipeStore opens the store as an os.Root, so every lock and recipe
// path stays inside it. A store that is a link or not a directory is
// refused. ok is false when there is no store, so nothing is installed.
func openRecipeStore() (root *os.Root, ok bool, err error) {
	dir, found := recipeStorePath()
	if !found {
		return nil, false, nil
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, configError("recipe store", "~/"+recipeStore, err)
	}
	if !info.IsDir() {
		return nil, false, fmt.Errorf("recipe store %q: must be a directory, not a link or a file", "~/"+recipeStore)
	}
	root, err = os.OpenRoot(dir)
	if err != nil {
		return nil, false, configError("recipe store", "~/"+recipeStore, err)
	}
	return root, true, nil
}

// readLock reads creep.lock from the store; an absent lock is an empty one.
func readLock(root *os.Root) (recipe.Lock, error) {
	data, err := readCappedFile(recipeOpener(root), "recipe lock", recipe.LockFile, recipe.MaxLockBytes)
	if errors.Is(err, errNoFile) {
		return recipe.NewLock(), nil
	}
	if err != nil {
		return recipe.Lock{}, err
	}
	return recipe.ParseLock(data)
}

// loadInstalledRecipes verifies every installed recipe before a scan opens
// anything: the lock parses, the policy allows each source, each file
// matches its checksum and parses. Any fault fails the scan closed (exit 2)
// with recipe.ErrTampered or the format error; none is skipped.
func loadInstalledRecipes(r *config.Resolved) ([]installedRecipe, error) {
	root, ok, err := openRecipeStore()
	if !ok || err != nil {
		return nil, err
	}
	defer root.Close()
	lock, err := readLock(root)
	if err != nil {
		return nil, err
	}
	patterns, enforced := r.PolicyRecipeSources()
	out := make([]installedRecipe, 0, len(lock.Recipes))
	for _, p := range lock.Recipes {
		data, err := verifyPin(root, p, patterns, enforced)
		if err != nil {
			return nil, err
		}
		out = append(out, installedRecipe{pin: p, data: data})
	}
	return out, nil
}

// verifyPin checks one lock entry against the policy, its file against its
// checksum, and the file's format. A missing file is tampering too.
func verifyPin(root *os.Root, p recipe.Pin, patterns []string, enforced bool) ([]byte, error) {
	src, err := p.Pinned()
	if err != nil {
		return nil, err
	}
	if !recipe.Allowed(src, patterns, enforced) {
		return nil, fmt.Errorf("installed recipe source %s: not in the %s recipe_sources allowlist; remove it from ~/%s/%s", src.Repository(), policyEnv, recipeStore, recipe.LockFile)
	}
	data, err := readCappedFile(recipeOpener(root), "installed recipe", filepath.FromSlash(p.Path()), recipe.MaxFileBytes)
	if errors.Is(err, errNoFile) {
		return nil, fmt.Errorf("%w: %s from %s is missing", recipe.ErrTampered, p.File, p.Source)
	}
	if err != nil {
		return nil, err
	}
	if err := p.Verify(data); err != nil {
		return nil, err
	}
	if _, err := recipe.Parse(data, checkRecipePoC); err != nil {
		return nil, fmt.Errorf("installed recipe %s from %s: %w", p.File, p.Source, err)
	}
	return data, nil
}

// writeSourceFiles writes src's files under <owner>/<repo>/<commit>/,
// replacing that directory if an earlier install left it. Every write is
// exclusive and inside the store's os.Root.
func writeSourceFiles(root *os.Root, src recipe.Source, files map[string][]byte) error {
	dir := path.Join(src.Owner, src.Name, src.Commit)
	if err := root.RemoveAll(filepath.FromSlash(dir)); err != nil {
		return configError("recipe store", dir, err)
	}
	if err := root.MkdirAll(filepath.FromSlash(dir), 0o700); err != nil {
		return configError("recipe store", dir, err)
	}
	for name, data := range files {
		if err := writeExclusive(root, path.Join(dir, name), data); err != nil {
			return err
		}
	}
	return nil
}

// writeLock replaces creep.lock through a temporary file and a rename, so
// a reader never sees half a lock.
func writeLock(root *os.Root, data []byte) error {
	tmp := recipe.LockFile + ".tmp"
	if err := root.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return configError("recipe lock", tmp, err)
	}
	if err := writeExclusive(root, tmp, data); err != nil {
		return err
	}
	if err := root.Rename(tmp, recipe.LockFile); err != nil {
		_ = root.Remove(tmp)
		return configError("recipe lock", recipe.LockFile, err)
	}
	return nil
}

// writeExclusive creates name (slash separated) in root, never over a
// file or through a link; a failed write removes what it created.
func writeExclusive(root *os.Root, name string, data []byte) error {
	file := filepath.FromSlash(name)
	f, err := root.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return configError("recipe store", name, err)
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = root.Remove(file)
		return configError("recipe store", name, err)
	}
	return nil
}

// removeOldCommits removes src's other commit directories, which the new
// lock no longer lists.
func removeOldCommits(root *os.Root, src recipe.Source) error {
	repo := path.Join(src.Owner, src.Name)
	entries, err := fs.ReadDir(root.FS(), repo)
	if err != nil {
		return configError("recipe store", repo, err)
	}
	for _, entry := range entries {
		if entry.Name() == src.Commit {
			continue
		}
		if err := root.RemoveAll(filepath.FromSlash(path.Join(repo, entry.Name()))); err != nil {
			return configError("recipe store", repo, err)
		}
	}
	return nil
}
