package recipestore

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/sneakercreepers/creep/internal/recipe"
)

// Install writes the files under <owner>/<repo>/<commit>/ in the store,
// then the lock. A source's earlier install is replaced: its old commit
// directory is removed only after the new lock is written, so a failure
// leaves a lock whose files either all exist or fail the scan.
func (s Store) Install(src recipe.Source, files map[string][]byte) error {
	dir, ok := Path()
	if !ok {
		return errors.New("recipe add: no home directory to install into")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return pathError("recipe store", "~/"+Dir, err)
	}
	root, found, err := open()
	if err != nil || !found {
		return errors.Join(err, errors.New("recipe add: the recipe store could not be opened"))
	}
	defer root.Close()
	lock, err := s.readLock(root)
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

// writeSourceFiles writes src's files under <owner>/<repo>/<commit>/,
// replacing that directory if an earlier install left it. Every write is
// exclusive and inside the store's os.Root.
func writeSourceFiles(root *os.Root, src recipe.Source, files map[string][]byte) error {
	dir := path.Join(src.Owner, src.Name, src.Commit)
	if err := root.RemoveAll(filepath.FromSlash(dir)); err != nil {
		return pathError("recipe store", dir, err)
	}
	if err := root.MkdirAll(filepath.FromSlash(dir), 0o700); err != nil {
		return pathError("recipe store", dir, err)
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
		return pathError("recipe lock", tmp, err)
	}
	if err := writeExclusive(root, tmp, data); err != nil {
		return err
	}
	if err := root.Rename(tmp, recipe.LockFile); err != nil {
		_ = root.Remove(tmp)
		return pathError("recipe lock", recipe.LockFile, err)
	}
	return nil
}

// writeExclusive creates name (slash separated) in root, never over a
// file or through a link; a failed write removes what it created.
func writeExclusive(root *os.Root, name string, data []byte) error {
	file := filepath.FromSlash(name)
	f, err := root.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return pathError("recipe store", name, err)
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = root.Remove(file)
		return pathError("recipe store", name, err)
	}
	return nil
}

// removeOldCommits removes src's other commit directories, which the new
// lock no longer lists.
func removeOldCommits(root *os.Root, src recipe.Source) error {
	repo := path.Join(src.Owner, src.Name)
	entries, err := fs.ReadDir(root.FS(), repo)
	if err != nil {
		return pathError("recipe store", repo, err)
	}
	for _, entry := range entries {
		if entry.Name() == src.Commit {
			continue
		}
		if err := root.RemoveAll(filepath.FromSlash(path.Join(repo, entry.Name()))); err != nil {
			return pathError("recipe store", repo, err)
		}
	}
	return nil
}
