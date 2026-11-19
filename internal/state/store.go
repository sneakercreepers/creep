package state

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

const (
	fileMode = 0o600
	dirMode  = 0o700

	runsDir    = "runs"
	cacheDir   = "cache"
	eventsFile = "events.jsonl"
)

var (
	// ErrCorrupt means a state file is torn, oversized or does not decode.
	// It is never repaired or skipped: the caller starts a new run.
	ErrCorrupt = errors.New("state file corrupt")
	// ErrUnsupportedVersion means a line was written by a newer creep.
	ErrUnsupportedVersion = errors.New("unsupported state version")
	// ErrUnsafePath means a state path is a link, not a regular file or
	// directory, or writable by other users.
	ErrUnsafePath = errors.New("unsafe state path")
)

// Store is a state directory. Every file access goes through an os.Root, so
// no name can escape it.
type Store struct {
	dir    string
	root   *os.Root
	secret []byte
}

// Open opens the state directory dir, creating it with mode 0700 if missing.
// secret (normally UserSecret) authenticates every line written and read,
// so state that did not come from this user's creep is never trusted.
func Open(dir string, secret []byte) (*Store, error) {
	if len(secret) != SecretBytes {
		return nil, fmt.Errorf("state dir: secret must be %d bytes", SecretBytes)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	if err := makeStateDir(abs); err != nil {
		return nil, err
	}
	before, err := checkDir(abs, os.Lstat)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		_ = root.Close()
		return nil, fmt.Errorf("state dir %q changed while opening: %w", abs, ErrUnsafePath)
	}
	if err := ignoreAll(root); err != nil {
		_ = root.Close()
		return nil, err
	}
	return &Store{dir: abs, root: root, secret: bytes.Clone(secret)}, nil
}

// Close releases the directory handle.
func (s *Store) Close() error {
	return s.root.Close()
}

// makeStateDir creates abs if missing. A file or link planted in its place
// is refused as ErrUnsafePath on every OS (MkdirAll's own error for it is
// "path not found" on Windows).
func makeStateDir(abs string) error {
	if info, err := os.Lstat(abs); err == nil && !info.IsDir() { //nolint:gosec // G703: abs is the state directory the caller chose; a link there is refused here
		return fmt.Errorf("state dir %q: not a directory: %w", abs, ErrUnsafePath)
	}
	if err := os.MkdirAll(abs, dirMode); err != nil { //nolint:gosec // G703: as above; Open checks the result through checkDir and os.Root
		return fmt.Errorf("state dir: %w", err)
	}
	return nil
}

// checkDir refuses a directory that is a link or writable by other users.
func checkDir(name string, lstat func(string) (fs.FileInfo, error)) (fs.FileInfo, error) {
	info, err := lstat(name)
	if err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	os.SameFile(info, info) // pin the Windows file ID now, not at comparison time
	if !info.IsDir() {
		return nil, fmt.Errorf("state dir %q: not a directory: %w", name, ErrUnsafePath)
	}
	if looseMode(info) {
		return nil, fmt.Errorf("state dir %q: writable by others: %w", name, ErrUnsafePath)
	}
	return info, nil
}

// ensureDir creates the top-level directory name inside the store if missing
// and checks it.
func (s *Store) ensureDir(name string) error {
	if err := s.root.Mkdir(name, dirMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("state dir %s: %w", name, err)
	}
	_, err := checkDir(name, s.root.Lstat)
	return err
}

// openRegular opens an existing regular file for reading (and appending, if
// appendMode) without following a link or blocking on a FIFO.
func (s *Store) openRegular(name string, appendMode bool) (*os.File, error) {
	before, err := s.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	os.SameFile(before, before)
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file: %w", name, ErrUnsafePath)
	}
	flag := os.O_RDONLY
	if appendMode {
		flag = os.O_RDWR | os.O_APPEND
	}
	f, err := s.root.OpenFile(name, flag|nonblockFlag, 0)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, fmt.Errorf("%s changed while opening: %w", name, ErrUnsafePath)
	}
	return f, nil
}

// readBounded reads all of name, refusing more than limit bytes.
func (s *Store) readBounded(name string, limit int64) ([]byte, error) {
	f, err := s.openRegular(name, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes: %w", name, limit, ErrCorrupt)
	}
	return data, nil
}

// writeAtomic writes data to name through a synced temporary file and a
// rename, so a crash leaves either the old file or the new one.
func (s *Store) writeAtomic(name string, data []byte) error {
	tmp := path.Join(path.Dir(name), ".tmp-"+randomHex(8))
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		// os.Root has no Rename before Go 1.25 (go.mod says 1.24). Both names
		// sit in a 0700 directory that ensureDir checked is not a link.
		err = os.Rename(s.abs(tmp), s.abs(name))
	}
	if err != nil {
		_ = s.root.Remove(tmp)
		return fmt.Errorf("write %s: %w", name, err)
	}
	return syncDir(s.root, path.Dir(name))
}

// ignoreAll writes a .gitignore that ignores the whole state directory when
// none is there, so git add -A does not commit egress.log, payloads (code
// the model saw) or run state (pentest P7). O_EXCL never opens an existing
// entry: a .gitignore, link or FIFO already there is left alone.
func ignoreAll(root *os.Root) error {
	f, err := root.OpenFile(".gitignore", os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("state dir: .gitignore: %w", err)
	}
	if _, err := f.WriteString("# Written by creep: run state, egress.log and reports stay local.\n*\n"); err != nil {
		_ = f.Close()
		return fmt.Errorf("state dir: .gitignore: %w", err)
	}
	return f.Close()
}

// abs turns a slash-separated store name into a host path.
func (s *Store) abs(name string) string {
	return filepath.Join(s.dir, filepath.FromSlash(name))
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return hex.EncodeToString(b)
}
