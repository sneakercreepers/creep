package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/report"
)

// outsideMarker is in the code outside the repository a link points to:
// no request may carry it.
const outsideMarker = "outside_repository_marker"

// outsideCode is a directory outside the repository holding a route with a
// shell sink.
func outsideCode(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	code := flaskRoute + "# " + outsideMarker + "\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// symlinkOrSkip makes a symbolic link, skipping where the platform or
// account cannot (Windows without Developer Mode).
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
}

// walkWithLink writes files under a temporary repository, adds one link
// with makeLink and walks it.
func walkWithLink(t *testing.T, files map[string]string, makeLink func(t *testing.T, repo string)) repoFiles {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil { //nolint:gosec // G703: names from the test table
			t.Fatal(err)
		}
	}
	makeLink(t, dir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := walkRepo(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// A directory link is listed whatever its name, never followed (#214): a
// symlink on Unix, a junction on Windows (linkDir). So is a link creep
// cannot resolve inside the repository (its target is outside, missing or
// absolute), which could be a directory. A
// link resolving to a file keeps the old rule (listed only when named as
// source), and a link in an installed tree is vendor, like its files.
func TestWalkListsDirectoryLinks(t *testing.T) {
	outside := outsideCode(t)
	venv := withGitIndex(map[string]string{"main.py": "x = 1\n", ".venv/pyvenv.cfg": "home = /usr\n", ".venv/lib/site.py": "x = 1\n"}, []string{".venv"})
	tests := []struct {
		name      string
		files     map[string]string
		link      func(t *testing.T, repo string)
		wantPaths []string
		wantGaps  []report.NotEvaluated
	}{
		{"directory link out of the repository", map[string]string{"main.py": "x = 1\n"},
			func(t *testing.T, repo string) { linkDir(t, outside, filepath.Join(repo, "web")) },
			[]string{"main.py"}, []report.NotEvaluated{{Path: "web", Reason: report.SkipNotRegular}}},
		{"directory link inside the repository", map[string]string{"real/app.py": "x = 1\n"},
			func(t *testing.T, repo string) { linkDir(t, filepath.Join(repo, "real"), filepath.Join(repo, "web")) },
			[]string{"real/app.py"}, []report.NotEvaluated{{Path: "web", Reason: report.SkipNotRegular}}},
		{"directory link with a dotted name", map[string]string{"main.py": "x = 1\n"},
			func(t *testing.T, repo string) { linkDir(t, outside, filepath.Join(repo, "conf.d")) },
			[]string{"main.py"}, []report.NotEvaluated{{Path: "conf.d", Reason: report.SkipNotRegular}}},
		{"relative symlink to a directory", map[string]string{"real/app.py": "x = 1\n"},
			func(t *testing.T, repo string) { symlinkOrSkip(t, "real", filepath.Join(repo, "web")) },
			[]string{"real/app.py"}, []report.NotEvaluated{{Path: "web", Reason: report.SkipNotRegular}}},
		{"symlink out of the repository", map[string]string{"main.py": "x = 1\n"},
			func(t *testing.T, repo string) { symlinkOrSkip(t, outside, filepath.Join(repo, "web")) },
			[]string{"main.py"}, []report.NotEvaluated{{Path: "web", Reason: report.SkipNotRegular}}},
		{"dangling link", map[string]string{"main.py": "x = 1\n"},
			func(t *testing.T, repo string) { symlinkOrSkip(t, "missing", filepath.Join(repo, "notes.txt")) },
			[]string{"main.py"}, []report.NotEvaluated{{Path: "notes.txt", Reason: report.SkipNotRegular}}},
		{"link to a file with a non-source name", map[string]string{"README.md": "# x\n"},
			func(t *testing.T, repo string) { symlinkOrSkip(t, "README.md", filepath.Join(repo, "notes.txt")) },
			[]string{"README.md"}, nil},
		{"absolute link to a file in the repository", map[string]string{"README.md": "# x\n"},
			func(t *testing.T, repo string) {
				symlinkOrSkip(t, filepath.Join(repo, "README.md"), filepath.Join(repo, "notes.txt"))
			},
			[]string{"README.md"}, []report.NotEvaluated{{Path: "notes.txt", Reason: report.SkipNotRegular}}},
		{"directory link in an installed venv", venv,
			func(t *testing.T, repo string) {
				linkDir(t, filepath.Join(repo, ".venv", "lib"), filepath.Join(repo, ".venv", "lib64"))
			},
			[]string{"main.py"}, []report.NotEvaluated{
				{Path: ".venv/lib/site.py", Reason: report.SkipVendor}, {Path: ".venv/lib64", Reason: report.SkipVendor},
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := walkWithLink(t, tt.files, tt.link)
			if !slices.Equal(got.paths, tt.wantPaths) || !slices.Equal(got.gaps, tt.wantGaps) {
				t.Fatalf("paths %v gaps %+v, want %v and %+v", got.paths, got.gaps, tt.wantPaths, tt.wantGaps)
			}
		})
	}
}

// Through the CLI (#214 acceptance): a directory link is listed as
// not_regular and the run is incomplete (exit 4, ADR 0009), and no request
// carries the code it points to; in an installed tree it is vendor, by
// design, and the run stays clean.
func TestScanDirectoryLinkExitCode(t *testing.T) {
	tests := []struct {
		name       string
		files      map[string]string
		link       [2]string // target, link; a relative target is under the repository
		wantCode   int
		wantReason string
		want       string
	}{
		{"link out of the repository", map[string]string{"main.py": helloRoute}, [2]string{"", "web"},
			exitcode.Incomplete, string(report.SkipNotRegular), "web  not_regular"},
		{"link in an installed venv",
			withGitIndex(map[string]string{"main.py": helloRoute, ".venv/pyvenv.cfg": "home = /usr\n", ".venv/lib/site.py": "x = 1\n"}, []string{".venv"}),
			[2]string{".venv/lib", ".venv/lib64"}, exitcode.OK, "", ".venv/lib64  vendor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outside := outsideCode(t)
			cfg := scanRepo(t, tt.files, "")
			target := outside
			if tt.link[0] != "" {
				abs, err := filepath.Abs(filepath.FromSlash(tt.link[0]))
				if err != nil {
					t.Fatal(err)
				}
				target = abs
			}
			linkDir(t, target, filepath.FromSlash(tt.link[1]))
			deps, leaked := watchPayloads(fakeDeps(&fakeModel{verdict: map[string]string{"command_injection": "vulnerable"}}, calibrate.TierM))
			code, out, errOut := runScanWith(deps, "scan", "--config", cfg)
			if code != tt.wantCode || !strings.Contains(out, tt.want) {
				t.Fatalf("exit %d, want %d and %q\n%s\n%s", code, tt.wantCode, tt.want, out, errOut)
			}
			if *leaked {
				t.Fatal("a request carried code from outside the repository")
			}
			checkJSONReport(t, tt.wantReason)
		})
	}
}

// watchPayloads wraps deps so that leaked turns true when a request
// carries outsideMarker.
func watchPayloads(deps scanDeps) (scanDeps, *bool) {
	leaked := new(bool)
	connect := deps.connect
	deps.connect = func(cfg *config.Resolved, dir string, w io.Writer) (modelLink, error) {
		link, err := connect(cfg, dir, w)
		send := link.send
		link.send = func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
			*leaked = *leaked || bytes.Contains(c.Payload, []byte(outsideMarker))
			return send(ctx, c)
		}
		return link, err
	}
	return deps, leaked
}
