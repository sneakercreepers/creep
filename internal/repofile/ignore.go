package repofile

import (
	"bytes"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Ignored is a mark an author put on a file that discovery read: it labels
// a file read in full with no candidate, never hides one. The zero value
// means no mark.
type Ignored uint8

// Marks.
const (
	// IgnoredGenerated: a generator marker in the first lines.
	IgnoredGenerated Ignored = iota + 1
	// IgnoredMinified: nine tenths of the bytes on lines longer than
	// minifiedLineBytes. A .min name alone does not count: the name is the
	// author's say-so (pentest P4).
	IgnoredMinified
)

// String returns the mark name.
func (r Ignored) String() string {
	switch r {
	case 0:
		return "none"
	case IgnoredGenerated:
		return "generated"
	case IgnoredMinified:
		return "minified"
	}
	return "unknown"
}

const (
	// generatedHeadBytes and generatedHeadLines bound the marker search,
	// so the check costs the same on any file and a marker deep in a file
	// does not count.
	generatedHeadBytes = 1024
	generatedHeadLines = 5
	// minifiedLineBytes is the line length past which a line counts as
	// minified; hand-written text stays far below it.
	minifiedLineBytes = 500
	minifiedMinBytes  = 1024
)

// IgnoreReason reports the mark the file with contents src carries, or 0.
// The rules read bytes only, never a name or comment syntax, so they hold
// for any language (#366). name must be relative to the repository root
// (slash- or backslash-separated): an absolute or escaping name is an
// error. A mark is the author's say-so: the caller believes it only for a
// file read in full with no candidate (ADR 0017).
func IgnoreReason(name string, src []byte) (Ignored, error) {
	if _, err := repoRelative(name); err != nil {
		return 0, err
	}
	switch {
	case hasGeneratedMarker(src):
		return IgnoredGenerated, nil
	case minified(src):
		return IgnoredMinified, nil
	}
	return 0, nil
}

// repoRelative normalizes a repo-relative name to a clean slash path. The
// separator follows the host, like the walk that produced the name: on
// Windows '\' separates, and elsewhere it is a byte of a legal file name
// (#194). A drive-letter name is refused on every host.
func repoRelative(name string) (string, error) {
	slash := filepath.ToSlash(name)
	clean := path.Clean(slash)
	switch {
	case slash == "" || clean == ".":
		return "", fmt.Errorf("path %q: empty", name)
	case strings.HasPrefix(slash, "/") || (len(slash) > 1 && slash[1] == ':'):
		return "", fmt.Errorf("path %q: not relative to the repository root", name)
	case clean == ".." || strings.HasPrefix(clean, "../"):
		return "", fmt.Errorf("path %q: escapes the repository root", name)
	}
	return clean, nil
}

// atGenerated is "@generated" as a whole word.
var atGenerated = regexp.MustCompile(`(^|[^a-z0-9_])@generated([^a-z0-9_]|$)`)

// hasGeneratedMarker reports whether one of the first generatedHeadLines
// lines, in the first generatedHeadBytes, carries a generator marker in
// any case: "@generated" as a word, or "generated" with "do not edit" or
// "do not modify". Any comment syntax counts, since none is parsed.
func hasGeneratedMarker(src []byte) bool {
	head := bytes.TrimPrefix(src[:min(len(src), generatedHeadBytes)], []byte{0xef, 0xbb, 0xbf}) // UTF-8 BOM
	lines := strings.SplitN(string(head), "\n", generatedHeadLines+1)
	for _, line := range lines[:min(len(lines), generatedHeadLines)] {
		l := strings.ToLower(line)
		if atGenerated.MatchString(l) {
			return true
		}
		if strings.Contains(l, "generated") && (strings.Contains(l, "do not edit") || strings.Contains(l, "do not modify")) {
			return true
		}
	}
	return false
}

// minified reports a dense file: nine tenths of its bytes on lines longer
// than minifiedLineBytes, so one long line padding readable text is not
// enough (pentest P4).
func minified(src []byte) bool {
	if len(src) < minifiedMinBytes {
		return false
	}
	long := 0
	for line := range bytes.Lines(src) {
		if len(line) > minifiedLineBytes {
			long += len(line)
		}
	}
	return long*10 >= len(src)*9
}
