package gitindex

import (
	"crypto/sha1" //nolint:gosec // G505: git's index checksum
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gitindex/gitindextest"
)

// TestParse: every index version and hash git writes is read whole;
// anything cut short, unsigned, out of range or needing an extension creep
// does not know is an error, so no made-up or missing path can prove a
// vendor tree installed.
func TestParse(t *testing.T) {
	long := strings.Repeat("d/", 200) + "deep.py" // strips more than 127 bytes in version 4
	paths := []string{"app.py", long, "node_modules/x/app.js", "node_modules/x/lib/a.js", "src/main.py"}
	tests := []struct {
		name string
		data []byte
		want []string // nil means an error
	}{
		{"version 2", gitindextest.Build(gitindextest.Spec{Version: 2, Paths: paths}), paths},
		{"version 3 extended flags", gitindextest.Build(gitindextest.Spec{Version: 3, Paths: paths, Extended: true}), paths},
		{"version 4 prefix-compressed", gitindextest.Build(gitindextest.Spec{Version: 4, Paths: paths}), paths},
		{"version 4 extended", gitindextest.Build(gitindextest.Spec{Version: 4, Paths: paths, Extended: true}), paths},
		{"sha-256", gitindextest.Build(gitindextest.Spec{Version: 2, HashLen: sha256.Size, Paths: paths}), paths},
		{"sha-256 version 4", gitindextest.Build(gitindextest.Spec{Version: 4, HashLen: sha256.Size, Paths: paths}), paths},
		{"no entries", gitindextest.Build(gitindextest.Spec{Version: 2}), []string{}},
		{"optional extensions", gitindextest.Build(gitindextest.Spec{Version: 2, Paths: paths, Ext: append(gitindextest.Extension("TREE", []byte("x")), gitindextest.Extension("UNTR", nil)...)}), paths},
		{"split index", gitindextest.Build(gitindextest.Spec{Version: 2, Paths: paths, Ext: gitindextest.Extension("link", make([]byte, 20))}), nil},
		{"sparse index", gitindextest.Build(gitindextest.Spec{Version: 2, Paths: paths, Ext: gitindextest.Extension("sdir", nil)}), nil},
		{"extension past the end", gitindextest.Build(gitindextest.Spec{Version: 2, Paths: paths, Ext: []byte("TREE\x00\x00\x01\x00")}), nil},
		{"trailing bytes", gitindextest.Build(gitindextest.Spec{Version: 2, Paths: paths, Ext: []byte("TRE")}), nil},
		{"unsigned (index.skipHash)", gitindextest.Build(gitindextest.Spec{Version: 2, Paths: paths, NoSign: true}), nil},
		{"version 1", gitindextest.Build(gitindextest.Spec{Version: 1, Paths: paths}), nil},
		{"version 5", gitindextest.Build(gitindextest.Spec{Version: 5, Paths: paths}), nil},
		{"more entries than written", gitindextest.Build(gitindextest.Spec{Version: 2, Paths: paths, Count: 9}), nil},
		{"version 4 more entries than written", gitindextest.Build(gitindextest.Spec{Version: 4, Paths: paths, Count: 9}), nil},
		{"extended flag in version 2", gitindextest.Build(gitindextest.Spec{Version: 2, Paths: paths, Extended: true}), nil},
		{"empty path", gitindextest.Build(gitindextest.Spec{Version: 2, Paths: []string{""}}), nil},
		{"path too long", gitindextest.Build(gitindextest.Spec{Version: 2, Paths: []string{strings.Repeat("a", MaxPathBytes+1)}}), nil},
		{"version 4 path grows too long", gitindextest.Build(gitindextest.Spec{Version: 4, Paths: growingPaths(MaxPathBytes + 1)}), nil},
		{"empty", nil, nil},
		{"only a checksum", gitindextest.Sign(nil, sha1.Size, false), nil},
		{"short header", gitindextest.Sign([]byte("DIRC\x00\x00\x00\x02"), sha1.Size, false), nil},
	}
	tests = append(tests, corruptIndexes(paths)...)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.data)
			if tt.want == nil {
				if err == nil || !errors.Is(err, ErrInvalid) {
					t.Fatalf("Parse = %q, %v; want an ErrInvalid error", got, err)
				}
				return
			}
			if err != nil || !slices.Equal(got, tt.want) {
				t.Fatalf("Parse = %q, %v; want %q", got, err, tt.want)
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
	v2 := gitindextest.Build(gitindextest.Spec{Version: 2, Paths: []string{"a.py"}})
	body := slices.Clone(v2[:len(v2)-sha1.Size])
	body[headerSize+statBytes+sha1.Size+2+len("a.py")+1] = 'x' // padding byte
	v4 := gitindextest.Build(gitindextest.Spec{Version: 4, Paths: paths[:1]})
	strip := slices.Clone(v4[:len(v4)-sha1.Size])
	strip[headerSize+statBytes+sha1.Size+2] = 7 // drop 7 bytes from an empty previous path
	unterminated := slices.Clone(v4[:len(v4)-sha1.Size-1])
	open := slices.Clone(v4[:headerSize+statBytes+sha1.Size+2])
	open = append(open, 0x80) // a varint that never ends
	signature := slices.Clone(v2[:len(v2)-sha1.Size])
	signature[3] = 'X'
	return []struct {
		name string
		data []byte
		want []string
	}{
		{"bad padding", gitindextest.Sign(body, sha1.Size, false), nil},
		{"wrong signature", gitindextest.Sign(signature, sha1.Size, false), nil},
		{"version 4 strip past the previous path", gitindextest.Sign(strip, sha1.Size, false), nil},
		{"version 4 path not terminated", gitindextest.Sign(unterminated, sha1.Size, false), nil},
		{"version 4 varint cut short", gitindextest.Sign(open, sha1.Size, false), nil},
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

// TestParseHostileBytes: any byte of a valid index changed, and the
// checksum fixed up, never panics, and an index that still reads gives
// only paths of bounded length.
func TestParseHostileBytes(t *testing.T) {
	for _, version := range []uint32{2, 3, 4} {
		valid := gitindextest.Build(gitindextest.Spec{Version: version, Paths: []string{"a.py", "node_modules/x/i.js", "node_modules/x/j.js"}, Extended: version > 2})
		body := valid[:len(valid)-sha1.Size]
		for i := range body {
			for _, b := range []byte{0x00, 0x7f, 0x80, 0xff} {
				mutated := slices.Clone(body)
				mutated[i] = b
				paths, err := Parse(gitindextest.Sign(mutated, sha1.Size, false))
				for _, p := range paths {
					if err == nil && (p == "" || len(p) > MaxPathBytes) {
						t.Fatalf("v%d byte %d = %#x: path of length %d", version, i, b, len(p))
					}
				}
			}
		}
	}
}

// TestVarint checks the test's encoder against git's decoder on the
// boundaries where it adds a byte.
func TestVarint(t *testing.T) {
	for _, v := range []int{0, 1, 127, 128, 255, 16511, 16512, 4096} {
		r := reader{data: gitindextest.Varint(v)}
		got, err := r.varint(1 << 20)
		if err != nil || got != v || r.off != len(r.data) {
			t.Errorf("varint(%x) = %d, %v; want %d", gitindextest.Varint(v), got, err, v)
		}
	}
}
