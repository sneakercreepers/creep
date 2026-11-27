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

// writeTree writes files (slash names) under dir.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil { //nolint:gosec // G703: names from the test table
			t.Fatal(err)
		}
	}
}

// walkWithLink writes files under a temporary repository, adds links with
// makeLink and walks it.
func walkWithLink(t *testing.T, files map[string]string, makeLink func(t *testing.T, repo string)) repoFiles {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, files)
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

// linkCase is one repository with a link the walk must not follow.
type linkCase struct {
	name      string
	files     map[string]string
	link      func(t *testing.T, repo string)
	wantPaths []string
	wantGaps  []report.NotEvaluated
}

func runLinkCases(t *testing.T, tests []linkCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := walkWithLink(t, tt.files, tt.link)
			if !slices.Equal(got.paths, tt.wantPaths) || !slices.Equal(got.gaps, tt.wantGaps) {
				t.Fatalf("paths %v gaps %+v, want %v and %+v", got.paths, got.gaps, tt.wantPaths, tt.wantGaps)
			}
		})
	}
}

// notRegular is the one gap a listed link leaves.
func notRegular(path string) []report.NotEvaluated {
	return []report.NotEvaluated{{Path: path, Reason: report.SkipNotRegular}}
}

// A link to a directory the walk does not reach at its own path is listed
// whatever its name, never followed (#214): one whose target does not name
// a walked entry over walked names (outside, missing, a loop, absolute,
// through another link, a Windows junction) and one into the root's .git
// or .creep. A link the root resolves to a directory the walk
// covers is not (a pnpm or workspace link), nor is one to a file with a
// non-source name. A listed link in an installed tree is vendor. linkDir
// makes an absolute symlink on Unix and a junction on Windows.
func TestWalkListsDirectoryLinks(t *testing.T) {
	outside := outsideCode(t)
	main := map[string]string{"main.py": "x = 1\n"}
	real := map[string]string{"real/app.py": "x = 1\n"}
	at := func(repo string, name ...string) string { return filepath.Join(append([]string{repo}, name...)...) }
	runLinkCases(t, []linkCase{
		{"directory link out of the repository", main,
			func(t *testing.T, repo string) { linkDir(t, outside, at(repo, "web")) }, []string{"main.py"}, notRegular("web")},
		{"absolute directory link or junction inside the repository", real,
			func(t *testing.T, repo string) { linkDir(t, at(repo, "real"), at(repo, "web")) }, []string{"real/app.py"}, notRegular("web")},
		{"directory link with a dotted name", main,
			func(t *testing.T, repo string) { linkDir(t, outside, at(repo, "conf.d")) }, []string{"main.py"}, notRegular("conf.d")},
		{"relative symlink to a walked directory", real,
			func(t *testing.T, repo string) { symlinkOrSkip(t, "real", at(repo, "web")) }, []string{"real/app.py"}, nil},
		// real\web -> ..\real and src\me -> . made os.Root.Stat panic on
		// Windows (Go 1.27.4, #214 tester H1); the walk no longer stats links.
		{"relative symlink up to a walked directory", real,
			func(t *testing.T, repo string) {
				symlinkOrSkip(t, filepath.Join("..", "real"), at(repo, "real", "web"))
			}, []string{"real/app.py"}, nil},
		{"relative symlink to its own directory", map[string]string{"src/app.py": "x = 1\n"},
			func(t *testing.T, repo string) { symlinkOrSkip(t, ".", at(repo, "src", "me")) }, []string{"src/app.py"}, nil},
		{"relative symlink through another link", real,
			func(t *testing.T, repo string) {
				symlinkOrSkip(t, "real", at(repo, "l"))
				sep := string(filepath.Separator) // not filepath.Join, which would clean l/.. away
				symlinkOrSkip(t, "l"+sep+".."+sep+"real", at(repo, "web"))
			}, []string{"real/app.py"}, notRegular("web")},
		{"workspace link back into the repository", map[string]string{"packages/app/index.js": "x()\n", "node_modules/left/package.json": "{}"},
			func(t *testing.T, repo string) {
				symlinkOrSkip(t, filepath.Join("..", "packages", "app"), at(repo, "node_modules", "app"))
			}, []string{"node_modules/left/package.json", "packages/app/index.js"}, nil},
		{"relative symlink into .git", map[string]string{".git/hooks/x.py": "x = 1\n"},
			func(t *testing.T, repo string) { symlinkOrSkip(t, filepath.Join(".git", "hooks"), at(repo, "web")) }, nil, notRegular("web")},
		{"relative symlink to .creep", map[string]string{".creep/x.py": "x = 1\n"},
			func(t *testing.T, repo string) { symlinkOrSkip(t, ".creep", at(repo, "web")) }, nil, notRegular("web")},
		{"relative symlink loop", main,
			func(t *testing.T, repo string) { symlinkOrSkip(t, "loop", at(repo, "loop")) }, []string{"main.py"}, notRegular("loop")},
		{"symlink out of the repository", main,
			func(t *testing.T, repo string) { symlinkOrSkip(t, outside, at(repo, "web")) }, []string{"main.py"}, notRegular("web")},
		{"dangling link", main,
			func(t *testing.T, repo string) { symlinkOrSkip(t, "missing", at(repo, "notes.txt")) }, []string{"main.py"}, notRegular("notes.txt")},
		{"link to a file with a non-source name", map[string]string{"README.md": "# x\n"},
			func(t *testing.T, repo string) { symlinkOrSkip(t, "README.md", at(repo, "notes.txt")) }, []string{"README.md"}, nil},
		{"absolute link to a file in the repository", map[string]string{"README.md": "# x\n"},
			func(t *testing.T, repo string) { symlinkOrSkip(t, at(repo, "README.md"), at(repo, "notes.txt")) },
			[]string{"README.md"}, notRegular("notes.txt")},
	})
}

// In an ignored, untracked tree a listed link is vendor, like the tree's
// files; a relative one the walk covers (lib64 -> lib) is not listed.
func TestWalkDirectoryLinksInInstalledTree(t *testing.T) {
	venv := withGitIndex(map[string]string{"main.py": "x = 1\n", ".gitignore": ".venv/\n", ".venv/lib/site.py": "x = 1\n"}, []string{".venv"})
	site := report.NotEvaluated{Path: ".venv/lib/site.py", Reason: report.SkipVendor}
	runLinkCases(t, []linkCase{
		{"absolute link or junction", venv,
			func(t *testing.T, repo string) {
				linkDir(t, filepath.Join(repo, ".venv", "lib"), filepath.Join(repo, ".venv", "lib64"))
			},
			[]string{".gitignore", "main.py"}, []report.NotEvaluated{site, {Path: ".venv/lib64", Reason: report.SkipVendor}}},
		{"relative symlink", venv,
			func(t *testing.T, repo string) { symlinkOrSkip(t, "lib", filepath.Join(repo, ".venv", "lib64")) },
			[]string{".gitignore", "main.py"}, []report.NotEvaluated{site}},
	})
}

// The root's .git and .creep are skipped whatever their type (#214 tester
// L1): a link or junction there is not listed, and a worktree's .git file,
// which holds a local absolute path, is never sent to discovery.
func TestWalkSkipsRootStateEntriesOfAnyType(t *testing.T) {
	outside := outsideCode(t)
	main := map[string]string{"main.py": "x = 1\n"}
	runLinkCases(t, []linkCase{
		{"worktree .git file", map[string]string{"main.py": "x = 1\n", ".git": "gitdir: /home/me/src/repo/.git/worktrees/x\n"},
			func(*testing.T, string) {}, []string{"main.py"}, nil},
		{".git link or junction", main,
			func(t *testing.T, repo string) { linkDir(t, outside, filepath.Join(repo, ".git")) }, []string{"main.py"}, nil},
		{".creep link or junction", main,
			func(t *testing.T, repo string) { linkDir(t, outside, filepath.Join(repo, stateDir)) }, []string{"main.py"}, nil},
	})
}

// Through the CLI (#214 acceptance): a directory link out of the
// repository is listed as not_regular and the run is incomplete (exit 4,
// ADR 0009), and no request carries the code it points to; a workspace
// link back into the repository and a link in an installed tree keep the
// run clean.
func TestScanDirectoryLinkExitCode(t *testing.T) {
	tests := []struct {
		name       string
		files      map[string]string
		link       func(t *testing.T, outside string)
		wantCode   int
		wantReason string
		want       string
	}{
		{"link out of the repository", map[string]string{"main.py": helloRoute},
			func(t *testing.T, outside string) { linkDir(t, outside, "web") },
			exitcode.Incomplete, string(report.SkipNotRegular), "web  not_regular"},
		{"workspace link back into the repository", map[string]string{"main.py": helloRoute, "packages/app/index.js": "x = 1;\n"},
			func(t *testing.T, _ string) {
				if err := os.Mkdir("node_modules", 0o700); err != nil {
					t.Fatal(err)
				}
				symlinkOrSkip(t, filepath.Join("..", "packages", "app"), filepath.Join("node_modules", "app"))
			}, exitcode.OK, "", "coverage:"},
		{"link in an ignored tree",
			withGitIndex(map[string]string{"main.py": helloRoute, ".gitignore": ".venv/\n", ".venv/lib/site.py": "x = 1\n"}, []string{".venv"}),
			func(t *testing.T, _ string) {
				abs, err := filepath.Abs(filepath.Join(".venv", "lib"))
				if err != nil {
					t.Fatal(err)
				}
				linkDir(t, abs, filepath.Join(".venv", "lib64"))
			}, exitcode.OK, "", ".venv/lib64  vendor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outside := outsideCode(t)
			cfg := scanRepo(t, tt.files, "")
			tt.link(t, outside)
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
