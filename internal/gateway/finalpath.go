package gateway

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The program-path checks mirror internal/repofile's finalpath.go (ADR 0013)
// and add the device and UNC refusal. The gateway keeps its own copy so its
// imports stay limited to what its row in the layer table names, and the
// rule is small enough to hold twice.

// maxLinkHops bounds link resolution, so a link cycle fails instead of
// looping.
const maxLinkHops = 64

var errNotAbsolute = errors.New("not an absolute path")

// isDeviceOrUNC reports a Windows device path (\\.\, //./) or a UNC path
// (\\host\share), after any verbatim prefix is removed. Running a program
// from a share would authenticate to that host over SMB, outside the
// gateway's allowlist.
func isDeviceOrUNC(p string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	p = stripVerbatim(p)
	return len(p) >= 2 && isSeparator(rune(p[0])) && isSeparator(rune(p[1]))
}

// finalPath returns the absolute path p names once every symbolic link
// and, on Windows, every junction is resolved, with any \\?\ verbatim
// prefix removed. filepath.EvalSymlinks does not follow mount points
// (Go 1.23), so this walks the components itself.
func finalPath(p string) (string, error) {
	p = filepath.Clean(stripVerbatim(p))
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%s: %w", p, errNotAbsolute)
	}
	vol := filepath.VolumeName(p)
	done, rest := vol+string(filepath.Separator), splitPath(p[len(vol):])
	for hops := 0; len(rest) > 0; {
		next := filepath.Join(done, rest[0])
		rest = rest[1:]
		info, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if !isLink(info) {
			done = next
			continue
		}
		if hops++; hops > maxLinkHops {
			return "", fmt.Errorf("%s: too many links", p)
		}
		target, err := linkTarget(next, done)
		if err != nil {
			return "", err
		}
		vol = filepath.VolumeName(target)
		done, rest = vol+string(filepath.Separator), append(splitPath(target[len(vol):]), rest...)
	}
	return done, nil
}

// linkTarget reads link and makes its target absolute against dir, the
// directory that holds the link.
func linkTarget(link, dir string) (string, error) {
	target, err := os.Readlink(link)
	if err != nil {
		return "", err
	}
	target = stripVerbatim(target)
	switch {
	case target == "":
		return "", fmt.Errorf("%s: empty link target: %w", link, errNotAbsolute)
	case filepath.IsAbs(target):
	case filepath.VolumeName(target) != "":
		return "", fmt.Errorf("%s: drive-relative target: %w", link, errNotAbsolute)
	case isSeparator(rune(target[0])):
		target = filepath.VolumeName(dir) + target // root-relative on Windows
	default:
		target = filepath.Join(dir, target)
	}
	return filepath.Clean(target), nil
}

// underDir reports whether path or one of its ancestors is the same
// directory as root, by file identity: case, 8.3 names, substituted drives
// and roots reached through a link or junction all match. path must be
// final.
func underDir(path, root string) (bool, error) {
	rootInfo, err := os.Stat(root)
	if err != nil {
		return false, err
	}
	for dir := path; ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return false, err
		}
		if os.SameFile(info, rootInfo) {
			return true, nil
		}
		if filepath.Dir(dir) == dir {
			return false, nil
		}
	}
}

// isLink reports a symbolic link or, on Windows, a junction: since Go 1.23
// Lstat reports mount points as irregular files. Readlink refuses other
// reparse points, so they fail closed.
func isLink(info fs.FileInfo) bool {
	if info.Mode()&fs.ModeSymlink != 0 {
		return true
	}
	return runtime.GOOS == "windows" && info.Mode()&fs.ModeIrregular != 0
}

// stripVerbatim removes the Windows \\?\ and \??\ prefixes (and their
// forward-slash spellings), so a verbatim path compares like a normal one;
// \\?\UNC\host\share becomes \\host\share.
func stripVerbatim(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	for _, prefix := range []string{`\\?\`, `\??\`, `//?/`} {
		if len(p) < len(prefix) || !strings.EqualFold(p[:len(prefix)], prefix) {
			continue
		}
		rest := p[len(prefix):]
		if len(rest) >= 4 && strings.EqualFold(rest[:4], `UNC\`) {
			return `\\` + rest[4:]
		}
		return rest
	}
	return p
}

func splitPath(p string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(p, isSeparator) {
		if part != "." {
			out = append(out, part)
		}
	}
	return out
}

func isSeparator(r rune) bool { return r == filepath.Separator || r == '/' }
