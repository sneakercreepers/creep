package cli

import (
	"context"
	"math"
	"os"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/gitindex"
)

// TestIndexMatchesTree (#380): an index is trusted only when it agrees
// with the tree. An edit after git recorded a file (newer mtime) and a
// deleted file agree; a size the disk does not hold with no later edit, a
// mode git never writes, a file that is a directory on disk, a path the
// root refuses, an index with no tracked file on disk and a passed
// deadline do not.
func TestIndexMatchesTree(t *testing.T) {
	repo := t.TempDir()
	writeTreeFile(t, repo, "a.py", "print(1)\n") // 9 bytes
	writeTreeFile(t, repo, "dir/b.py", "x\n")
	past := uint32(time.Now().Add(-time.Hour).Unix()) //nolint:gosec // G115: a 2026 time fits
	file := func(path string, size, mtime uint32) gitindex.Entry {
		return gitindex.Entry{Path: path, Mode: gitModeFile, Size: size, MtimeSec: mtime}
	}
	tests := []struct {
		name    string
		entries []gitindex.Entry
		expired bool
		want    bool
	}{
		{"same size", []gitindex.Entry{file("a.py", 9, math.MaxUint32)}, false, true},
		{"executable", []gitindex.Entry{{Path: "a.py", Mode: gitModeExec, Size: 9}}, false, true},
		{"edited after git recorded it", []gitindex.Entry{file("a.py", 3, past)}, false, true},
		{"size the disk does not hold", []gitindex.Entry{file("a.py", 3, math.MaxUint32)}, false, false},
		{"deleted beside a present file", []gitindex.Entry{file("a.py", 9, 0), file("gone.py", 1, 0)}, false, true},
		{"no tracked file on disk", []gitindex.Entry{file("gone.py", 1, 0)}, false, false},
		{"empty index", nil, false, false},
		{"links and gitlinks only", []gitindex.Entry{{Path: "l", Mode: gitModeLink}, {Path: "dir", Mode: gitModeGitlink}}, false, false},
		{"link beside a file", []gitindex.Entry{file("a.py", 9, 0), {Path: "a.py", Mode: gitModeLink}}, false, true},
		{"mode git never writes", []gitindex.Entry{file("a.py", 9, 0), {Path: "dir/b.py", Mode: 0o100600, Size: 2}}, false, false},
		{"zero mode", []gitindex.Entry{file("a.py", 9, 0), {Path: "dir/b.py"}}, false, false},
		{"directory tracked as a file", []gitindex.Entry{file("a.py", 9, 0), file("dir", 0, 0)}, false, false},
		{"path escaping the root", []gitindex.Entry{file("a.py", 9, 0), file("../outside.py", 1, 0)}, false, false},
		{"absolute path", []gitindex.Entry{file("a.py", 9, 0), file("/etc/passwd", 1, 0)}, false, false},
		{"past the deadline", []gitindex.Entry{file("a.py", 9, 0)}, true, false},
	}
	root, err := os.OpenRoot(repo)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.expired {
				cancel()
			}
			if got := indexMatchesTree(ctx, root, tt.entries); got != tt.want {
				t.Errorf("indexMatchesTree = %v, want %v", got, tt.want)
			}
		})
	}
}
