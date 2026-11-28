package discover

import (
	_ "embed" // the format table is data in formats.txt
	"fmt"
	"path"
	"strings"
	"sync"
	"unicode/utf8"
)

// Format is a known non-code file format from formats.txt; the zero value
// means the name says nothing and the file's bytes decide (#366).
type Format uint8

// formatNames are the format IDs; Format(i+1) is formatNames[i]. The
// first binaryFormats are binary formats, then the text formats never
// opened, then config.
var formatNames = []string{
	"image", "font", "media", "archive", "object", "document", "store",
	"prose", "lockfile", "data", "vector", "config",
}

// binaryFormats counts the leading binary formats in formatNames.
const binaryFormats = 7

// formatConfig is structured text that may be security-relevant (a policy,
// app settings, rules code loads): read like any text file, but listed
// not_code instead of too_large when it does not fit one discovery call,
// since a file that size is data, not settings (#366 tester).
var formatConfig = Format(indexOf(formatNames, "config") + 1) //nolint:gosec // G115: a short list

// String returns the format ID, or "unknown".
func (f Format) String() string { return nameOf(formatNames, int(f)) }

// opened reports whether discovery opens a file of this format: a binary
// format is believed only when the bytes look binary, so a text file named
// like an image is still read.
func (f Format) opened() bool { return f.text() || int(f) <= binaryFormats }

// text reports a file discovery reads as text unless its bytes are binary:
// one no row names, or config.
func (f Format) text() bool { return f == 0 || f == formatConfig }

// formatTable holds the exact name, glob and extension rules, all
// lowercased.
type formatTable struct {
	names, exts map[string]Format
	globs       []formatGlob
}

type formatGlob struct {
	prefix, suffix string
	format         Format
}

//go:embed formats.txt
var formatData string

// loadFormats parses the embedded table once; formats_test.go keeps the
// shipped one valid.
var loadFormats = sync.OnceValues(func() (formatTable, error) {
	return parseFormats(formatData)
})

func parseFormats(data string) (formatTable, error) {
	t := formatTable{names: map[string]Format{}, exts: map[string]Format{}}
	for n, fields := range tableRows(data) {
		if err := t.add(fields); err != nil {
			return formatTable{}, fmt.Errorf("formats.txt line %d: %w", n, err)
		}
	}
	return t, nil
}

func (t *formatTable) add(fields []string) error {
	if len(fields) != 3 {
		return fmt.Errorf("want <match> <pattern> <format>, got %d fields", len(fields))
	}
	i := indexOf(formatNames, fields[2])
	if i < 0 {
		return fmt.Errorf("unknown format %q", fields[2])
	}
	f, key := Format(i+1), fields[1] //nolint:gosec // G115: a short list
	if key != strings.ToLower(key) {
		return fmt.Errorf("pattern %q is not lowercase", key)
	}
	switch fields[0] {
	case "name":
		return addOnce(t.names, key, f)
	case "ext":
		return addOnce(t.exts, key, f)
	case "glob":
		prefix, suffix, ok := strings.Cut(key, "*")
		if !ok || strings.Contains(suffix, "*") {
			return fmt.Errorf("glob %q needs exactly one *", key)
		}
		t.globs = append(t.globs, formatGlob{prefix, suffix, f})
		return nil
	}
	return fmt.Errorf("unknown match %q", fields[0])
}

func addOnce(m map[string]Format, key string, f Format) error {
	if _, dup := m[key]; dup {
		return fmt.Errorf("%q appears twice", key)
	}
	m[key] = f
	return nil
}

// formatOf is the known format of the file at name, from its lowercased
// base name, or zero.
func (t formatTable) formatOf(name string) Format {
	base := strings.ToLower(baseName(name))
	if f, ok := t.names[base]; ok {
		return f
	}
	for _, g := range t.globs {
		if len(base) >= len(g.prefix)+len(g.suffix) && strings.HasPrefix(base, g.prefix) && strings.HasSuffix(base, g.suffix) {
			return g.format
		}
	}
	return t.exts[path.Ext(base)]
}

// looksBinary reports bytes no text file holds. A file named as a binary
// format is binary when its first binaryProbeBytes hold a NUL or are not
// UTF-8. A text file (no row names it, or config) is binary only when its head holds a NUL and
// is not UTF-8: one that is UTF-8 apart from a NUL is text that hides a
// byte, which addFile lists read_failed so the run is incomplete, as for
// labeled source (#268, #366 tester). A head cut inside a character still
// counts as UTF-8.
func looksBinary(f Format, content []byte) bool {
	head := content[:min(len(content), binaryProbeBytes)]
	if len(content) > binaryProbeBytes {
		head = dropCutRune(head)
	}
	if f.text() {
		return hasNUL(content) && !utf8.Valid(head)
	}
	return hasNUL(content) || !utf8.Valid(head)
}

// dropCutRune drops a last character the probe cut in two.
func dropCutRune(head []byte) []byte {
	for i := len(head) - 1; i >= max(0, len(head)-utf8.UTFMax); i-- {
		if utf8.RuneStart(head[i]) {
			if !utf8.FullRune(head[i:]) {
				return head[:i]
			}
			return head
		}
	}
	return head
}

// utf16BOM reports a UTF-16 byte order mark: text whose ASCII characters
// carry NUL bytes, so a NUL does not make it binary.
func utf16BOM(content []byte) bool {
	return len(content) >= 2 && (content[0] == 0xff && content[1] == 0xfe || content[0] == 0xfe && content[1] == 0xff)
}
