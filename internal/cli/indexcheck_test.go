package cli

import (
	"context"
	"math"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/gitindex"
)

// TestIndexMatchesTree (#380): an index is trusted only when it agrees
// with the tree as one git wrote does. An edit after git recorded a file
// (newer mtime) and a deleted file agree; a size the disk does not hold
// with no later edit, no tracked file with its recorded size, a zero
// mtime, another executable bit, a mode git never writes, a file that is a
// directory on disk, a path the root refuses and a passed deadline do not.
func TestIndexMatchesTree(t *testing.T) {
	repo := t.TempDir()
	writeTreeFile(t, repo, "a.py", "print(1)\n") // 9 bytes, mode 0600
	writeTreeFile(t, repo, "dir/b.py", "x\n")
	past := uint32(time.Now().Add(-time.Hour).Unix()) //nolint:gosec // G115: a 2026 time fits
	file := func(path string, size, mtime uint32) gitindex.Entry {
		return gitindex.Entry{Path: path, Mode: gitModeFile, Size: size, MtimeSec: mtime}
	}
	a := file("a.py", 9, past)
	tests := []struct {
		name    string
		entries []gitindex.Entry
		expired bool
		want    bool
	}{
		{"same size", []gitindex.Entry{file("a.py", 9, math.MaxUint32)}, false, true},
		{"edited after git recorded it", []gitindex.Entry{a, file("dir/b.py", 7, past)}, false, true},
		{"only edited files", []gitindex.Entry{file("a.py", 3, past)}, false, false},
		{"size the disk does not hold", []gitindex.Entry{a, file("dir/b.py", 7, math.MaxUint32)}, false, false},
		{"zero mtime", []gitindex.Entry{file("a.py", 9, 0)}, false, false},
		{"executable bit git did not record", []gitindex.Entry{{Path: "a.py", Mode: gitModeExec, Size: 9, MtimeSec: past}}, false, runtime.GOOS == "windows"},
		{"deleted beside a present file", []gitindex.Entry{a, file("gone.py", 1, past)}, false, true},
		{"no tracked file on disk", []gitindex.Entry{file("gone.py", 1, past)}, false, false},
		{"empty index", nil, false, false},
		{"links and gitlinks only", []gitindex.Entry{{Path: "l", Mode: gitModeLink}, {Path: "dir", Mode: gitModeGitlink}}, false, false},
		{"link beside a file", []gitindex.Entry{a, {Path: "a.py", Mode: gitModeLink}}, false, true},
		{"mode git never writes", []gitindex.Entry{a, {Path: "dir/b.py", Mode: 0o100600, Size: 2, MtimeSec: past}}, false, false},
		{"zero mode", []gitindex.Entry{a, {Path: "dir/b.py"}}, false, false},
		{"directory tracked as a file", []gitindex.Entry{a, file("dir", 0, past)}, false, false},
		{"path escaping the root", []gitindex.Entry{a, file("../outside.py", 1, past)}, false, false},
		{"absolute path", []gitindex.Entry{a, file("/etc/passwd", 1, past)}, false, false},
		{"past the deadline", []gitindex.Entry{a}, true, false},
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
