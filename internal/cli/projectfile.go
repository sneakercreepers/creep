package cli

import (
	"errors"
	"fmt"
	"os"
)

// openProjectConfig opens ./creep.yaml, which comes from the repository being
// scanned: a link there could point at a UNC share or a file outside the
// repository. Checking the path with Lstat and then opening it by name leaves
// a window for a swap, so the opened file is also checked against the path.
func openProjectConfig(label, path string) (*os.File, os.FileInfo, error) {
	before, err := lstatNoLink(label, path)
	if err != nil {
		return nil, nil, err
	}
	return openSameFile(label, path, before)
}

// lstatNoLink rejects a symlink or other special entry at path itself.
func lstatNoLink(label, path string) (os.FileInfo, error) {
	info, err := os.Lstat(path) //nolint:gosec // G703: path is the fixed project file name; Lstat reads no content
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s %q: %w", label, path, errNoFile)
	}
	if err != nil {
		return nil, configError(label, path, err)
	}
	if info.Mode()&os.ModeType != 0 && !info.IsDir() {
		return nil, fmt.Errorf("%s %q: must be a regular file, not a link or special file", label, path)
	}
	// Windows reads the file ID of an Lstat result by path on first compare;
	// comparing now pins it to the entry just checked, not a later swap.
	os.SameFile(info, info)
	return info, nil
}

// openSameFile opens path without following a final link and accepts it only
// if it is still the entry before describes.
func openSameFile(label, path string, before os.FileInfo) (*os.File, os.FileInfo, error) {
	f, info, err := openConfigWith(openNoFollow, label, path)
	if err != nil {
		return nil, nil, err
	}
	if err := requireSameFile(label, path, before, info); err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// requireSameFile compares the opened file with the path before and after the
// open. The second Lstat matters on Windows, where open follows links: a
// link still in place is rejected by type, one swapped back by file ID.
func requireSameFile(label, path string, before, opened os.FileInfo) error {
	after, err := lstatNoLink(label, path)
	if err != nil {
		return err
	}
	if !os.SameFile(before, opened) || !os.SameFile(after, opened) {
		return fmt.Errorf("%s %q: changed while being opened", label, path)
	}
	if linkCount(opened) > 1 {
		return fmt.Errorf("%s %q: must not be a hard link", label, path)
	}
	return nil
}
