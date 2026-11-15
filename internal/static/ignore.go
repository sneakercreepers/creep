package static

import (
	"bytes"
	"fmt"
	"path"
	"strings"
)

// Ignored is why a file was listed but not evaluated. The zero value means
// the file was evaluated.
type Ignored uint8

// Reasons a file is not evaluated.
const (
	// IgnoredVendor: a path segment is a dependency directory
	// (vendorDirs).
	IgnoredVendor Ignored = iota + 1
	// IgnoredGenerated: a comment near the top marks the file as generated.
	IgnoredGenerated
	// IgnoredMinified: a JavaScript or TypeScript file named *.min.js or
	// whose average line is longer than minifiedLineBytes.
	IgnoredMinified
)

// String returns the reason name.
func (r Ignored) String() string {
	switch r {
	case 0:
		return "none"
	case IgnoredVendor:
		return "vendor"
	case IgnoredGenerated:
		return "generated"
	case IgnoredMinified:
		return "minified"
	}
	return "unknown"
}

// vendorDirs are directory names that hold third-party code, compared
// without case because the scanned repo may come from a case-insensitive
// file system.
var vendorDirs = []string{
	"vendor", "node_modules", "bower_components", "jspm_packages", "third_party",
	"site-packages", "dist-packages", "__pypackages__", ".venv", "venv",
}

const (
	// generatedHeadBytes bounds the generated-marker search, so the check
	// costs the same on any file and a marker deep in a file (a string in
	// code) does not count.
	generatedHeadBytes = 1024
	// minifiedLineBytes is the average line length past which a script is
	// treated as minified; hand-written code stays far below it.
	minifiedLineBytes = 500
	minifiedMinBytes  = 1024
)

// IgnoreReason reports why the file at a slash-separated path with contents
// src should not be parsed, or 0 when it should. Callers check it before
// parsing and record a non-zero reason with Extractor.AddIgnored, so the
// file is listed as not evaluated rather than dropped.
func IgnoreReason(name string, src []byte) Ignored {
	name = strings.ReplaceAll(name, "\\", "/")
	switch {
	case inVendorDir(name):
		return IgnoredVendor
	case hasGeneratedMarker(src):
		return IgnoredGenerated
	case minified(name, src):
		return IgnoredMinified
	}
	return 0
}

func inVendorDir(name string) bool {
	dirs := strings.Split(path.Dir(name), "/")
	for _, d := range dirs {
		for _, v := range vendorDirs {
			if strings.EqualFold(d, v) {
				return true
			}
		}
	}
	return false
}

// hasGeneratedMarker looks for a comment line in the head of the file that
// says "@generated", or says "generated" together with "do not edit" or
// "do not modify" (Go's "Code generated ... DO NOT EDIT.", protoc, many
// code generators).
func hasGeneratedMarker(src []byte) bool {
	head := src[:min(len(src), generatedHeadBytes)]
	for _, raw := range bytes.Split(head, []byte("\n")) {
		line := strings.ToLower(strings.TrimSpace(string(raw)))
		if !isCommentLine(line) {
			continue
		}
		if strings.Contains(line, "@generated") {
			return true
		}
		if strings.Contains(line, "generated") && (strings.Contains(line, "do not edit") || strings.Contains(line, "do not modify")) {
			return true
		}
	}
	return false
}

func isCommentLine(line string) bool {
	for _, p := range []string{"#", "//", "/*", "*"} {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}

// minified applies only to scripts: Python is never minified in practice,
// so a long Python line is parsed, not skipped.
func minified(name string, src []byte) bool {
	lang, ok := LanguageForPath(name)
	if !ok || lang == Python {
		return false
	}
	base := strings.ToLower(path.Base(name))
	stem := strings.TrimSuffix(base, path.Ext(base))
	if strings.HasSuffix(stem, ".min") || strings.HasSuffix(stem, "-min") {
		return true
	}
	lines := bytes.Count(src, []byte("\n")) + 1
	return len(src) >= minifiedMinBytes && len(src)/lines > minifiedLineBytes
}

// AddIgnored lists a file that was not evaluated, with the reason, so the
// report can show it as not covered. path is kept only in Locations.
func (e *Extractor) AddIgnored(name string, why Ignored) error {
	if why == 0 || why > IgnoredMinified {
		return fmt.Errorf("ignore %s: invalid reason %d", name, why)
	}
	if !fits(len(e.graph.Files) + 1) {
		return fmt.Errorf("ignore %s: %w", name, ErrGraphFull)
	}
	lang, _ := LanguageForPath(strings.ReplaceAll(name, "\\", "/"))
	id := FileID(len(e.graph.Files)) //nolint:gosec // G115: fits checked above
	e.graph.Files = append(e.graph.Files, File{ID: id, Language: lang, Ignored: why})
	e.locs.Files = append(e.locs.Files, name)
	return nil
}
