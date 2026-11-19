package gateway

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// errUnsafeRunDir marks a model run directory parent that another user
// could write to.
var errUnsafeRunDir = errors.New("model command: run directory parent is writable by others")

// userCacheDir is os.UserCacheDir; tests point it at a private directory.
var userCacheDir = os.UserCacheDir

// newRunRoot makes a fresh directory for one model call under
// <user cache>/creep/model (0700), never under the system temp directory.
// Model CLIs read files in parents of their working directory (Gemini CLI:
// the first .env up the tree and GEMINI.md files up to a .git), and on a
// shared machine any local user can plant those in /tmp. Here every parent
// up to the user cache directory is the user's own and closed to others.
func newRunRoot() (string, error) {
	cache, err := userCacheDir()
	if err != nil {
		return "", fmt.Errorf("model command: user cache dir: %w", err)
	}
	base := filepath.Join(cache, "creep", "model")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", fmt.Errorf("model command: run dir: %w", err)
	}
	if err := checkRunParents(cache, base); err != nil {
		return "", err
	}
	root, err := os.MkdirTemp(base, "run-")
	if err != nil {
		return "", fmt.Errorf("model command: run dir: %w", err)
	}
	return root, nil
}

// checkRunParents refuses a cache or creep directory that others can write
// to or that belongs to another user, and a model directory that is a link
// or open to others. The cache directory itself may be a link the user set
// up; the two creep directories below it may not.
func checkRunParents(cache, base string) error {
	checks := []struct {
		path string
		stat func(string) (os.FileInfo, error)
		mask os.FileMode
	}{
		{cache, os.Stat, 0o022},
		{filepath.Dir(base), os.Lstat, 0o022}, // shared with the calibration store
		{base, os.Lstat, 0o077},
	}
	for _, c := range checks {
		info, err := c.stat(c.path)
		if err != nil {
			return fmt.Errorf("model command: run dir: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("model command: %q is not a directory: %w", c.path, errUnsafeRunDir)
		}
		if err := checkAccess(c.path, info, c.mask, errUnsafeRunDir); err != nil {
			return fmt.Errorf("model command: %w", err)
		}
	}
	return nil
}
