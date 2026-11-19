package gitindex

import (
	"crypto/sha1" //nolint:gosec // G505: git's index checksum
	"crypto/sha256"
	"testing"

	"github.com/sneakercreepers/creep/internal/gitindex/gitindextest"
)

// FuzzParse feeds Parse index bodies signed with a valid checksum, so the
// fuzzer reaches the entry and extension readers instead of stopping at
// the checksum. Parse must never panic, and an index it accepts must hold
// only non-empty paths within MaxPathBytes and, together, MaxPathTotal.
// Run longer with: go test ./internal/gitindex -fuzz FuzzParse.
func FuzzParse(f *testing.F) {
	paths := []string{"app.py", "node_modules/x/app.js", "node_modules/x/lib/a.js"}
	for _, s := range []gitindextest.Spec{
		{Version: 2, Paths: paths},
		{Version: 3, Paths: paths, Extended: true},
		{Version: 4, Paths: paths},
		{Version: 2, Paths: paths, Ext: gitindextest.Extension("TREE", []byte("x"))},
		{Version: 2, Paths: paths, Ext: gitindextest.Extension("link", nil)},
		{Version: 4, HashLen: sha256.Size, Paths: paths},
	} {
		data := gitindextest.Build(s)
		hashLen := s.HashLen
		if hashLen == 0 {
			hashLen = sha1.Size
		}
		f.Add(data[:len(data)-hashLen], hashLen == sha256.Size)
	}
	f.Fuzz(func(t *testing.T, body []byte, useSHA256 bool) {
		hashLen := sha1.Size
		if useSHA256 {
			hashLen = sha256.Size
		}
		got, err := Parse(gitindextest.Sign(body, hashLen, false))
		if err != nil {
			return
		}
		total := 0
		for _, p := range got {
			total += len(p)
			if p == "" || len(p) > MaxPathBytes || total > MaxPathTotal {
				t.Fatalf("accepted a path of %d bytes (total %d)", len(p), total)
			}
		}
	})
}
