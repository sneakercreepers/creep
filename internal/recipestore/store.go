package recipestore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/sneakercreepers/creep/internal/recipe"
)

// Dir is where `creep recipe add` installs recipes and creep.lock, under
// the operator's home, next to the user config, never the scanned
// repository. Messages show it as "~/" + Dir.
const Dir = ".creep/recipes"

// ReadFunc reads the regular, singly linked file name (OS separators)
// inside root, at most limit bytes, without blocking on a FIFO. It returns
// an error wrapping fs.ErrNotExist when name does not exist.
type ReadFunc func(root *os.Root, label, name string, limit int64) ([]byte, error)

// Store reads and writes the recipe store with the caller's file rules.
type Store struct {
	Read ReadFunc
	PoC  recipe.PoCCheck // the rule a recipe's PoC must meet (ADR 0019)
}

// Policy is the org policy's recipe_sources allowlist; Enforced is false
// when the policy sets none.
type Policy struct {
	Patterns []string
	Enforced bool
}

// Installed is one lock entry whose file matched its checksum and parsed:
// bytes for recipe.Checker.Load, which alone makes it usable.
type Installed struct {
	Pin  recipe.Pin
	Data []byte
}

// Path is ~/.creep/recipes, or false with no home directory.
func Path() (string, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	return filepath.Join(home, filepath.FromSlash(Dir)), true
}

// open opens the store as an os.Root, so every lock and recipe path stays
// inside it. A store that is a link or not a directory is refused. ok is
// false when there is no store, so nothing is installed.
func open() (root *os.Root, ok bool, err error) {
	dir, found := Path()
	if !found {
		return nil, false, nil
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, pathError("recipe store", "~/"+Dir, err)
	}
	if !info.IsDir() {
		return nil, false, fmt.Errorf("recipe store %q: must be a directory, not a link or a file", "~/"+Dir)
	}
	root, err = os.OpenRoot(dir)
	if err != nil {
		return nil, false, pathError("recipe store", "~/"+Dir, err)
	}
	return root, true, nil
}

// readLock reads creep.lock from the store; an absent lock is an empty one.
func (s Store) readLock(root *os.Root) (recipe.Lock, error) {
	data, err := s.Read(root, "recipe lock", recipe.LockFile, recipe.MaxLockBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return recipe.NewLock(), nil
	}
	if err != nil {
		return recipe.Lock{}, err
	}
	return recipe.ParseLock(data)
}

// Load verifies every installed recipe before a scan opens anything: the
// lock parses, the policy allows each source, each file matches its
// checksum and parses. Any fault fails closed with recipe.ErrTampered or
// the format error; none is skipped.
func (s Store) Load(p Policy) ([]Installed, error) {
	root, ok, err := open()
	if !ok || err != nil {
		return nil, err
	}
	defer root.Close()
	lock, err := s.readLock(root)
	if err != nil {
		return nil, err
	}
	out := make([]Installed, 0, len(lock.Recipes))
	for _, pin := range lock.Recipes {
		data, err := s.verifyPin(root, pin, p)
		if err != nil {
			return nil, err
		}
		out = append(out, Installed{Pin: pin, Data: data})
	}
	return out, nil
}

// verifyPin checks one lock entry against the policy, its file against its
// checksum, and the file's format. A missing file is tampering too.
func (s Store) verifyPin(root *os.Root, pin recipe.Pin, p Policy) ([]byte, error) {
	src, err := pin.Pinned()
	if err != nil {
		return nil, err
	}
	if !recipe.Allowed(src, p.Patterns, p.Enforced) {
		return nil, fmt.Errorf("installed recipe source %s: not in the org policy's recipe_sources allowlist; remove it from ~/%s/%s", src.Repository(), Dir, recipe.LockFile)
	}
	data, err := s.Read(root, "installed recipe", filepath.FromSlash(pin.Path()), recipe.MaxFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s from %s is missing", recipe.ErrTampered, pin.File, pin.Source)
	}
	if err != nil {
		return nil, err
	}
	if err := pin.Verify(data); err != nil {
		return nil, err
	}
	if _, err := recipe.Parse(data, s.PoC); err != nil {
		return nil, fmt.Errorf("installed recipe %s from %s: %w", pin.File, pin.Source, err)
	}
	return data, nil
}

// pathError drops the *os.PathError wrapper, which would repeat the path
// unquoted and let control characters in it reach the terminal.
func pathError(label, path string, err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return fmt.Errorf("%s %q: %w", label, path, err)
}
