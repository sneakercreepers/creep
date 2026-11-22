package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// maxConfigBytes caps how much of a config file is read; real configs are a
// few KiB, so anything larger is a mistake or an attack.
const maxConfigBytes = 1 << 20

// errNoFile lets optional layers (user, project) tell "absent" from "broken".
var errNoFile = errors.New("file does not exist")

// openConfig opens path once and checks the opened file itself, so a device
// (NUL, CON, /dev/zero, a FIFO) or a swapped path cannot pass as a config
// file. label names the source in errors ("--config", "CREEP_POLICY").
func openConfig(label, path string) (*os.File, os.FileInfo, error) {
	return openConfigWith(openForCheck, label, path)
}

// openConfigWith is openConfig with the system open chosen by the caller, so
// the project file can be opened without following links.
func openConfigWith(open func(string) (*os.File, error), label, path string) (*os.File, os.FileInfo, error) {
	if err := checkConfigPath(label, path); err != nil {
		return nil, nil, err
	}
	f, err := open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("%s %q: %w", label, path, errNoFile)
	}
	if err != nil {
		return nil, nil, configError(label, path, err)
	}
	info, err := requireRegular(f)
	if err == nil {
		err = restoreBlocking(f)
	}
	if err != nil {
		f.Close()
		return nil, nil, configError(label, path, err)
	}
	return f, info, nil
}

// checkConfigPath rejects paths that are unsafe before any open happens.
// On Windows, opening a UNC path (\\host\share) authenticates to that host
// over SMB, which is network traffic outside the gateway. On Linux, /proc and
// /sys hold virtual files (/proc/self/environ) that look regular.
func checkConfigPath(label, path string) error {
	if runtime.GOOS == "windows" && isUNCOrDevice(path) {
		return fmt.Errorf("%s %q: UNC and device paths are not allowed", label, path)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	for _, p := range unixPaths(path) {
		if underVirtualFS(p) {
			return fmt.Errorf("%s %q: files under /proc, /sys and /dev are not allowed", label, path)
		}
	}
	return nil
}

func isUNCOrDevice(path string) bool {
	isSep := func(b byte) bool { return b == '\\' || b == '/' }
	if len(path) >= 2 && isSep(path[0]) && isSep(path[1]) {
		return true
	}
	return strings.HasPrefix(path, `\??\`) || strings.HasPrefix(path, `/??/`)
}

// unixPaths returns the absolute path and, when it resolves, the path with
// symlinks followed. Resolving is safe on Unix: it never touches the network.
func unixPaths(path string) []string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil
	}
	paths := []string{abs}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		paths = append(paths, real)
	}
	return paths
}

func underVirtualFS(abs string) bool {
	for _, root := range []string{"/proc", "/sys", "/dev"} {
		if abs == root || strings.HasPrefix(abs, root+"/") {
			return true
		}
	}
	return false
}

func requireRegular(f *os.File) (os.FileInfo, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, errors.New("is a directory")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return info, nil
}

// readConfigFile returns the raw bytes of a config file for the parser.
// Reading more or less than stat reported means the file is virtual or
// changed under us; either way it is not a config file to trust.
func readConfigFile(label, path string) ([]byte, error) {
	return readConfigWith(openConfig, label, path)
}

// configOpener opens a config file and returns it with its Fstat info.
type configOpener func(label, path string) (*os.File, os.FileInfo, error)

func readConfigWith(open configOpener, label, path string) ([]byte, error) {
	return readCappedFile(open, label, path, maxConfigBytes)
}

// readCappedFile reads the whole file open returns, at most limit bytes;
// --config and the --changed list share it, so both refuse the same files.
func readCappedFile(open configOpener, label, path string, limit int64) ([]byte, error) {
	f, info, err := open(label, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info.Size() > limit {
		return nil, fmt.Errorf("%s %q: larger than %d bytes", label, path, limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, configError(label, path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s %q: larger than %d bytes", label, path, limit)
	}
	if int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("%s %q: size changed while reading or not a real file", label, path)
	}
	return data, nil
}

// configError drops the *os.PathError wrapper, which would repeat the path
// unquoted and let control characters in it reach the terminal.
func configError(label, path string, err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}
	return fmt.Errorf("%s %q: %w", label, path, err)
}
