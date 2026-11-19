package gateway

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// errUnsafeRunDir marks a model run directory, or a directory above it,
// that another user could write to or that is a link.
var errUnsafeRunDir = errors.New("model command: run directory is not private")

// userCacheDir and userHomeDir are the os functions; tests point them at
// private directories.
var (
	userCacheDir = os.UserCacheDir
	userHomeDir  = os.UserHomeDir
)

// staleRunAge is how old a run directory must be before a later process
// removes it as left behind by a crash: far past the longest model call.
const staleRunAge = 24 * time.Hour

var staleRunsOnce sync.Once

// newRunRoot makes a fresh directory for one model call under
// <user cache>/creep/model (0700), never under the system temp directory.
// Model CLIs read files in parents of their working directory (Gemini CLI:
// the first .env up the tree and GEMINI.md files up to a .git; Codex:
// AGENTS.md), and on a shared machine any local user can plant those in
// /tmp. checkRunPath proves every directory from the run directory up to
// the home directory (or the volume root) is a real directory others
// cannot write to.
func newRunRoot() (string, error) {
	cache, home, err := userDirs()
	if err != nil {
		return "", err
	}
	base := filepath.Join(cache, "creep", "model")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", fmt.Errorf("model command: run dir: %w", err)
	}
	if err := checkRunPath(base, home); err != nil {
		return "", err
	}
	staleRunsOnce.Do(func() { removeStaleRuns(base, time.Now()) })
	root, err := os.MkdirTemp(base, "run-")
	if err != nil {
		return "", fmt.Errorf("model command: run dir: %w", err)
	}
	if err := writeStopFiles(root); err != nil {
		_ = os.RemoveAll(root)
		return "", err
	}
	return root, nil
}

// stopFiles are empty files in the run root, the parent of the working
// directory, that end the CLIs' upward searches inside creep's tree. The
// walk above checks directories only up to home; above it, a volume root
// such as C:\ lets any local user create folders (C:\.gemini\.env).
// Gemini CLI's findEnvFile returns the first .gemini/.env (trusted) or
// .env (untrusted) going up, so an empty one loads nothing and stops it;
// its GEMINI.md search ends at the first .git going up (file or directory),
// and an empty .git file is also an invalid gitfile, which stops git's own
// upward search with an error.
var stopFiles = []string{".env", filepath.Join(".gemini", ".env"), ".git"}

func writeStopFiles(root string) error {
	for _, name := range stopFiles {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("model command: run dir: %w", err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return fmt.Errorf("model command: run dir: %w", err)
		}
	}
	return nil
}

// userDirs returns the user cache and home directories, both absolute: a
// relative HOME or LocalAppData would put the run directory inside the
// current directory, which during a scan is the repository.
func userDirs() (cache, home string, err error) {
	if cache, err = userCacheDir(); err != nil {
		return "", "", fmt.Errorf("model command: user cache dir: %w", err)
	}
	if home, err = userHomeDir(); err != nil {
		return "", "", fmt.Errorf("model command: home dir: %w", err)
	}
	for _, d := range []string{cache, home} {
		if !filepath.IsAbs(d) {
			return "", "", fmt.Errorf("model command: %q is not an absolute path: %w", d, errUnsafeRunDir)
		}
	}
	return filepath.Clean(cache), filepath.Clean(home), nil
}

// checkRunPath walks from base up to home, or to the volume root when base
// is not under home. creep's own model and creep directories must also be
// the user's and closed to group and others (model) or to writes by them
// (creep, shared with the calibration store).
func checkRunPath(base, home string) error {
	if err := checkRunDir(base, 0o077, true); err != nil {
		return err
	}
	if err := checkRunDir(filepath.Dir(base), 0o022, true); err != nil {
		return err
	}
	for dir := filepath.Dir(filepath.Dir(base)); ; dir = filepath.Dir(dir) {
		if err := checkRunDir(dir, 0o002, false); err != nil {
			return err
		}
		if samePath(dir, home) || filepath.Dir(dir) == dir {
			return nil
		}
	}
}

// checkRunDir refuses a link or a non-directory, mode bits in mask (Unix;
// Windows reports no real modes, and LocalAppData under the profile is
// private by its ACL), and, when owned is set, another user's directory.
func checkRunDir(dir string, mask fs.FileMode, owned bool) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("model command: run dir: %w", err)
	}
	if info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 || !info.IsDir() {
		return fmt.Errorf("model command: %q is a link or not a directory: %w", dir, errUnsafeRunDir)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm()&mask != 0 {
		return fmt.Errorf("model command: %q has mode %v: %w", dir, info.Mode().Perm(), errUnsafeRunDir)
	}
	if owned && !ownedBySelf(info) {
		return fmt.Errorf("model command: %q is owned by another user: %w", dir, errUnsafeRunDir)
	}
	return nil
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// removeStaleRuns deletes run directories a crashed process left in base.
// Only real directories named run-* are removed; os.RemoveAll removes a
// link inside one without following it. Errors are ignored: a leftover
// directory wastes space, it is never reused.
func removeStaleRuns(base string, now time.Time) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "run-") || e.Type() != fs.ModeDir {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < staleRunAge {
			continue
		}
		_ = os.RemoveAll(filepath.Join(base, e.Name()))
	}
}
