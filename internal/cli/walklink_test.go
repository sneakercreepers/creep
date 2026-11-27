package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/report"
)

// Past the scan deadline no link is read (#260, #214 tester M2): every link
// that could be a directory is listed, even one the walk covers, so a
// crafted tree of links ends the run incomplete instead of stalling it.
func TestWalkListsLinksPastDeadline(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"real/app.py": "x = 1\n", "README.md": "# x\n"})
	symlinkOrSkip(t, "real", filepath.Join(dir, "web"))
	symlinkOrSkip(t, "README.md", filepath.Join(dir, "notes.txt"))
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	got, err := walkRepo(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	want := []report.NotEvaluated{{Path: "notes.txt", Reason: report.SkipNotRegular}, {Path: "web", Reason: report.SkipNotRegular}}
	if !slices.Equal(got.gaps, want) {
		t.Fatalf("gaps %+v, want %+v", got.gaps, want)
	}
}

// A link's target is followed over walked names only, and never past
// maxLinkSteps names.
func TestWalkedTreeReaches(t *testing.T) {
	tree := newWalkedTree()
	for _, d := range []string{"a", "a/b", "a/b/c"} {
		tree.add(d, true)
	}
	tree.add("a/f.txt", false)
	tests := []struct {
		rel, target string
		want        bool
	}{
		{"a/link", "b/c", true},
		{"a/b/link", "../f.txt", true},
		{"a/b/c/link", "../../..", true},
		{"a/b/c/link", "../../../..", false},
		{"a/link", "f.txt/..", false},
		{"a/link", "missing", false},
		{"a/link", "", false},
		{"a/link", "/a/b", false},
		{"link", "/a", false},  // names a walked directory, but the target is absolute
		{"link", `\a`, false},  // rooted on Windows; a plain name on Unix, not walked
		{"link", "C:a", false}, // a volume on Windows; a plain name on Unix, not walked
		{"link", strings.Repeat("a/../", maxLinkSteps/2) + "a", false},
		{"link", strings.Repeat("./", maxLinkSteps/2-1) + "a", true},
	}
	for _, tt := range tests {
		if got := tree.reaches(tt.rel, tt.target); got != tt.want {
			t.Errorf("reaches(%q, %q) = %v, want %v", tt.rel, tt.target, got, tt.want)
		}
	}
}

// How a link or special file is classified, with the mode the walk saw
// (#214 tester L1, L2): a FIFO, socket or device is never a directory and
// is not read; a reparse point that is not a symbolic link (ModeIrregular:
// a junction, a OneDrive placeholder) is a directory unless the root stats
// it as a regular file, the stand-in here for a placeholder, which no test
// can make.
func TestUnreachedByMode(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"file.txt": "x\n", "sub/a.txt": "x\n"})
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	tests := []struct {
		rel  string
		mode fs.FileMode
		want bool
	}{
		{"missing-pipe", fs.ModeNamedPipe, false},
		{"missing-socket", fs.ModeSocket, false},
		{"missing-device", fs.ModeDevice | fs.ModeCharDevice, false},
		{"file.txt", fs.ModeIrregular, false},
		{"sub", fs.ModeIrregular, true},
		{"missing", fs.ModeIrregular, true},
	}
	for _, tt := range tests {
		l := pendingLink{rel: tt.rel, mode: tt.mode}
		if got := unreached(context.Background(), root, l, newWalkedTree()); got != tt.want {
			t.Errorf("unreached(%q, %v) = %v, want %v", tt.rel, tt.mode, got, tt.want)
		}
	}
}

// A panic inside an os.Root call (Go 1.27.4 on Windows, #214 tester H1)
// comes back as errRootPanic, so the caller fails closed instead of
// crashing the scan.
func TestRecoverStat(t *testing.T) {
	stat := recoverStat(func(string) (fs.FileInfo, error) { panic("index out of range [1] with length 1") })
	if _, err := stat("real/web"); !errors.Is(err, errRootPanic) {
		t.Fatalf("err = %v, want errRootPanic", err)
	}
}

// The installed-tree check stats tracked names through links; a tracked
// link of the shape that panics os.Root on Windows must not crash the walk
// (#214 tester H1). Whatever the platform resolves, the walk ends.
func TestWalkSurvivesTrackedLinkUpward(t *testing.T) {
	files := withGitIndex(map[string]string{
		"main.py": "x = 1\n", ".gitignore": "node_modules/\n", "node_modules/@s/pkg/package.json": "{}", "node_modules/@s/pkg/index.js": "x()\n",
	}, []string{"node_modules"}, "node_modules/web")
	got := walkWithLink(t, files, func(t *testing.T, repo string) {
		symlinkOrSkip(t, filepath.Join("..", "node_modules"), filepath.Join(repo, "node_modules", "web"))
	})
	if !slices.Contains(got.paths, "main.py") {
		t.Fatalf("paths %v lack main.py", got.paths)
	}
}

// The documented worst case for links (ADR 0009 #214 amendment): 2,000
// links in a directory 120 levels deep, each with a 240-name target back
// to itself, cost one readlink and at most maxLinkSteps lookups each.
func BenchmarkWalkLinks(b *testing.B) {
	dir := b.TempDir()
	deep := filepath.Join(dir, filepath.Join(slices.Repeat([]string{"d"}, 120)...))
	if err := os.MkdirAll(deep, 0o700); err != nil {
		b.Fatal(err)
	}
	target := strings.Repeat("../", 120) + strings.Repeat("d/", 120)
	for i := range 2000 {
		if err := os.Symlink(target, filepath.Join(deep, "l"+strconv.Itoa(i))); err != nil {
			b.Skipf("no symlinks here: %v", err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	for b.Loop() {
		got, err := walkRepo(context.Background(), root)
		if err != nil || len(got.gaps) != 0 {
			b.Fatalf("err %v, gaps %d", err, len(got.gaps))
		}
	}
}
