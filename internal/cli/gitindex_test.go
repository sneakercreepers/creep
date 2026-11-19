package cli

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // G505: git's index checksum
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
)

// gitIndexSpec describes an index for buildGitIndex. A zero hashLen is
// SHA-1; noSign leaves the checksum zero, as index.skipHash does.
type gitIndexSpec struct {
	version  uint32
	hashLen  int
	paths    []string
	extended bool   // set the extended flag on every entry
	count    int    // entry count in the header; 0 means len(paths)
	ext      []byte // raw bytes after the entries
	noSign   bool
}

// buildGitIndex writes an index the way git does (gitformat-index.txt).
func buildGitIndex(s gitIndexSpec) []byte {
	if s.hashLen == 0 {
		s.hashLen = sha1.Size
	}
	count := s.count
	if count == 0 {
		count = len(s.paths)
	}
	var b bytes.Buffer
	b.WriteString("DIRC")
	b.Write(binary.BigEndian.AppendUint32(nil, s.version))
	b.Write(binary.BigEndian.AppendUint32(nil, uint32(count))) //nolint:gosec // G115: test sizes
	prev := ""
	for _, p := range s.paths {
		start := b.Len()
		b.Write(make([]byte, gitStatBytes+s.hashLen))
		flags := uint16(min(len(p), 0xfff)) //nolint:gosec // G115: bounded by min
		if s.extended {
			flags |= gitFlagExt
		}
		b.Write(binary.BigEndian.AppendUint16(nil, flags))
		if s.extended {
			b.Write([]byte{0, 0})
		}
		if s.version == 4 {
			common := commonPrefixLen(prev, p)
			b.Write(gitVarint(len(prev) - common))
			b.WriteString(p[common:])
			b.WriteByte(0)
		} else {
			b.WriteString(p)
			n := b.Len() - start
			b.Write(make([]byte, (n+8)&^7-n))
		}
		prev = p
	}
	b.Write(s.ext)
	return signGitIndex(b.Bytes(), s.hashLen, s.noSign)
}

func signGitIndex(body []byte, hashLen int, noSign bool) []byte {
	out := slices.Clone(body)
	switch {
	case noSign:
		return append(out, make([]byte, hashLen)...)
	case hashLen == sha256.Size:
		sum := sha256.Sum256(body)
		return append(out, sum[:]...)
	}
	sum := sha1.Sum(body) //nolint:gosec // G401: git's index checksum
	return append(out, sum[:]...)
}

func commonPrefixLen(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}

// gitVarint is git's encode_varint.
func gitVarint(v int) []byte {
	out := []byte{byte(v & 0x7f)}
	for v >>= 7; v > 0; v >>= 7 {
		v--
		out = append([]byte{0x80 | byte(v&0x7f)}, out...)
	}
	return out
}

func gitExtension(sig string, data []byte) []byte {
	out := append([]byte(sig), binary.BigEndian.AppendUint32(nil, uint32(len(data)))...) //nolint:gosec // G115: test sizes
	return append(out, data...)
}

// TestParseGitIndex: every index version and hash git writes is read whole;
// anything cut short, unsigned, out of range or needing an extension creep
// does not know is an error, so no made-up or missing path can prove a
// vendor tree installed.
func TestParseGitIndex(t *testing.T) {
	long := strings.Repeat("d/", 200) + "deep.py" // strips more than 127 bytes in version 4
	paths := []string{"app.py", long, "node_modules/x/app.js", "node_modules/x/lib/a.js", "src/main.py"}
	tests := []struct {
		name string
		data []byte
		want []string // nil means an error
	}{
		{"version 2", buildGitIndex(gitIndexSpec{version: 2, paths: paths}), paths},
		{"version 3 extended flags", buildGitIndex(gitIndexSpec{version: 3, paths: paths, extended: true}), paths},
		{"version 4 prefix-compressed", buildGitIndex(gitIndexSpec{version: 4, paths: paths}), paths},
		{"version 4 extended", buildGitIndex(gitIndexSpec{version: 4, paths: paths, extended: true}), paths},
		{"sha-256", buildGitIndex(gitIndexSpec{version: 2, hashLen: sha256.Size, paths: paths}), paths},
		{"sha-256 version 4", buildGitIndex(gitIndexSpec{version: 4, hashLen: sha256.Size, paths: paths}), paths},
		{"no entries", buildGitIndex(gitIndexSpec{version: 2}), []string{}},
		{"optional extensions", buildGitIndex(gitIndexSpec{version: 2, paths: paths, ext: append(gitExtension("TREE", []byte("x")), gitExtension("UNTR", nil)...)}), paths},
		{"split index", buildGitIndex(gitIndexSpec{version: 2, paths: paths, ext: gitExtension("link", make([]byte, 20))}), nil},
		{"sparse index", buildGitIndex(gitIndexSpec{version: 2, paths: paths, ext: gitExtension("sdir", nil)}), nil},
		{"extension past the end", buildGitIndex(gitIndexSpec{version: 2, paths: paths, ext: []byte("TREE\x00\x00\x01\x00")}), nil},
		{"trailing bytes", buildGitIndex(gitIndexSpec{version: 2, paths: paths, ext: []byte("TRE")}), nil},
		{"unsigned (index.skipHash)", buildGitIndex(gitIndexSpec{version: 2, paths: paths, noSign: true}), nil},
		{"version 1", buildGitIndex(gitIndexSpec{version: 1, paths: paths}), nil},
		{"version 5", buildGitIndex(gitIndexSpec{version: 5, paths: paths}), nil},
		{"more entries than written", buildGitIndex(gitIndexSpec{version: 2, paths: paths, count: 9}), nil},
		{"version 4 more entries than written", buildGitIndex(gitIndexSpec{version: 4, paths: paths, count: 9}), nil},
		{"extended flag in version 2", buildGitIndex(gitIndexSpec{version: 2, paths: paths, extended: true}), nil},
		{"empty path", buildGitIndex(gitIndexSpec{version: 2, paths: []string{""}}), nil},
		{"path too long", buildGitIndex(gitIndexSpec{version: 2, paths: []string{strings.Repeat("a", maxGitPathBytes+1)}}), nil},
		{"version 4 path grows too long", buildGitIndex(gitIndexSpec{version: 4, paths: growingPaths(maxGitPathBytes + 1)}), nil},
		{"empty", nil, nil},
		{"only a checksum", signGitIndex(nil, sha1.Size, false), nil},
		{"short header", signGitIndex([]byte("DIRC\x00\x00\x00\x02"), sha1.Size, false), nil},
	}
	tests = append(tests, corruptIndexes(paths)...)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGitIndex(tt.data)
			if tt.want == nil {
				if err == nil || !errors.Is(err, errGitIndex) {
					t.Fatalf("parseGitIndex = %q, %v; want an errGitIndex error", got, err)
				}
				return
			}
			if err != nil || !slices.Equal(got, tt.want) {
				t.Fatalf("parseGitIndex = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

// corruptIndexes are signed indexes whose entries break the format: a
// checksum proves only that the bytes are whole, not that git wrote them.
func corruptIndexes(paths []string) []struct {
	name string
	data []byte
	want []string
} {
	v2 := buildGitIndex(gitIndexSpec{version: 2, paths: []string{"a.py"}})
	body := slices.Clone(v2[:len(v2)-sha1.Size])
	body[gitHeaderSize+gitStatBytes+sha1.Size+2+len("a.py")+1] = 'x' // padding byte
	v4 := buildGitIndex(gitIndexSpec{version: 4, paths: paths[:1]})
	strip := slices.Clone(v4[:len(v4)-sha1.Size])
	strip[gitHeaderSize+gitStatBytes+sha1.Size+2] = 7 // drop 7 bytes from an empty previous path
	unterminated := slices.Clone(v4[:len(v4)-sha1.Size-1])
	open := slices.Clone(v4[:gitHeaderSize+gitStatBytes+sha1.Size+2])
	open = append(open, 0x80) // a varint that never ends
	signature := slices.Clone(v2[:len(v2)-sha1.Size])
	signature[3] = 'X'
	return []struct {
		name string
		data []byte
		want []string
	}{
		{"bad padding", signGitIndex(body, sha1.Size, false), nil},
		{"wrong signature", signGitIndex(signature, sha1.Size, false), nil},
		{"version 4 strip past the previous path", signGitIndex(strip, sha1.Size, false), nil},
		{"version 4 path not terminated", signGitIndex(unterminated, sha1.Size, false), nil},
		{"version 4 varint cut short", signGitIndex(open, sha1.Size, false), nil},
	}
}

// growingPaths is a version 4 index that keeps every byte of the path
// before and adds one, so a few bytes per entry expand to long paths.
func growingPaths(n int) []string {
	out := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, strings.Repeat("a", i))
	}
	return out
}

// TestParseGitIndexHostileBytes: any byte of a valid index changed, and the
// checksum fixed up, never panics, and an index that still reads gives
// only paths of bounded length.
func TestParseGitIndexHostileBytes(t *testing.T) {
	for _, version := range []uint32{2, 3, 4} {
		valid := buildGitIndex(gitIndexSpec{version: version, paths: []string{"a.py", "node_modules/x/i.js", "node_modules/x/j.js"}, extended: version > 2})
		body := valid[:len(valid)-sha1.Size]
		for i := range body {
			for _, b := range []byte{0x00, 0x7f, 0x80, 0xff} {
				mutated := slices.Clone(body)
				mutated[i] = b
				paths, err := parseGitIndex(signGitIndex(mutated, sha1.Size, false))
				for _, p := range paths {
					if err == nil && (p == "" || len(p) > maxGitPathBytes) {
						t.Fatalf("v%d byte %d = %#x: path of length %d", version, i, b, len(p))
					}
				}
			}
		}
	}
}

// TestTrackedPathsTouches: a tree is tracked when git holds anything in it,
// the tree itself, or a path above it (a submodule), compared without case;
// a sibling with the same prefix does not count.
func TestTrackedPathsTouches(t *testing.T) {
	tracked := newTrackedPaths([]string{"src/app.py", "node_modules/evil/app.js", "Web", "Node_Modules/Up/x.js", "node_modules/gitlink", "node_modules/evil-two.js"})
	tests := []struct {
		dir  string
		want bool
	}{
		{"node_modules/evil", true},
		{"node_modules/up", true},
		{"NODE_MODULES/EVIL", true},
		{"web/node_modules/x", true},
		{"node_modules/gitlink", true},
		{"src", true},
		{"node_modules/ev", false},
		{"node_modules/evil-two", false},
		{"node_modules/express", false},
		{"venv", false},
		{".venv", false},
	}
	for _, tt := range tests {
		if got := tracked.touches(tt.dir); got != tt.want {
			t.Errorf("touches(%q) = %v, want %v", tt.dir, got, tt.want)
		}
	}
	if (trackedPaths{}).touches("node_modules/x") {
		t.Error("an empty index tracks a tree")
	}
}

// TestGitVarint checks the test's encoder against git's decoder on the
// boundaries where it adds a byte.
func TestGitVarint(t *testing.T) {
	for _, v := range []int{0, 1, 127, 128, 255, 16511, 16512, 4096} {
		r := gitIndexReader{data: gitVarint(v)}
		got, err := r.varint(1 << 20)
		if err != nil || got != v || r.off != len(r.data) {
			t.Errorf("varint(%x) = %d, %v; want %d", gitVarint(v), got, err, v)
		}
	}
}
