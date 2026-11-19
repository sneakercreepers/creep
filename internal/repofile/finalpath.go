package repofile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// maxLinkHops bounds link resolution, so a link cycle fails instead of
// looping.
const maxLinkHops = 64

var errNotAbsolute = errors.New("not an absolute path")

// OutsideRepo resolves bin to its final path and reports it when neither
// that path nor any directory above it is the repository or the current
// directory. Any error fails closed (ok is false): a binary creep cannot
// place is never run (ADR 0013).
func OutsideRepo(bin, repo string) (final string, ok bool) {
	if repo == "" || !filepath.IsAbs(repo) {
		return "", false
	}
	final, err := finalPath(bin)
	if err != nil {
		return "", false
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for _, root := range []string{repo, cwd} {
		if under, err := underDir(final, root); err != nil || under {
			return "", false
		}
	}
	return final, true
}

// underDir reports whether path or one of its ancestors is the same
// directory as root. It compares file identities, not strings, so case,
// 8.3 short names, a substituted drive or a root reached through a link or
// junction all match. path must be final (no links left).
func underDir(path, root string) (bool, error) {
	rootInfo, err := os.Stat(root)
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", root, err)
	}
	for dir := path; ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return false, fmt.Errorf("stat %s: %w", dir, err)
		}
		if os.SameFile(info, rootInfo) {
			return true, nil
		}
		if filepath.Dir(dir) == dir {
			return false, nil
		}
	}
}

// finalPath returns the absolute path p names once every symbolic link
// and, on Windows, every junction (mount point) is resolved, with any
// \\?\ verbatim prefix removed. filepath.EvalSymlinks no longer follows
// mount points (Go 1.23), so this walks the components itself.
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
	target = filepath.Clean(target)
	if !filepath.IsAbs(target) {
		return "", fmt.Errorf("%s: %w", link, errNotAbsolute)
	}
	return target, nil
}

// isLink reports a symbolic link or, on Windows, a junction: since Go 1.23
// Lstat reports mount points as irregular files, not links. Readlink
// refuses other reparse points, so they fail closed.
func isLink(info fs.FileInfo) bool {
	if info.Mode()&fs.ModeSymlink != 0 {
		return true
	}
	return runtime.GOOS == "windows" && info.Mode()&fs.ModeIrregular != 0
}

// stripVerbatim removes the Windows \\?\ and \??\ prefixes, so a verbatim
// path compares like a normal one. A volume GUID path keeps no drive and
// is then refused as not absolute.
func stripVerbatim(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	for _, prefix := range []string{`\\?\`, `\??\`} {
		if !strings.HasPrefix(p, prefix) {
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
