package scanrun

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/sneakercreepers/creep/internal/repofile"
)

// TestRunLeavesOutRepoGitleaksIgnore (#226): the scanned repository is
// untrusted, so its root .gitleaksignore never hides a finding. gitleaks
// runs once per other root entry, the run says the file was skipped, and
// a repository that leaves no clean way to scan fails closed unstarted.
func TestRunLeavesOutRepoGitleaksIgnore(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, repo string)
		want     Outcome
		failure  Failure
		sources  []string // logged by the fake, repository-relative; nil when never started
		findings []string
		skipped  bool
	}{
		{"ignore file naming a root secret is left out", func(t *testing.T, repo string) {
			writeFile(t, filepath.Join(repo, ".gitleaksignore"), "README.md:generic-api-key:3\napp/config.py:aws-access-token:3\n")
			writeFile(t, filepath.Join(repo, "README.md"), "x")
			writeFile(t, filepath.Join(repo, "app", "config.py"), "x")
		}, Evaluated, FailNone, []string{"README.md", "app"}, []string{"README.md", "README.md", "app/config.py", "app/config.py"}, true},
		{"ignore directory is left out", func(t *testing.T, repo string) {
			mkdir(t, filepath.Join(repo, ".gitleaksignore"))
			writeFile(t, filepath.Join(repo, "app", "config.py"), "x")
		}, Evaluated, FailNone, []string{"app"}, []string{"app/config.py", "app/config.py"}, true},
		{".git is not a source", func(t *testing.T, repo string) {
			writeFile(t, filepath.Join(repo, ".gitleaksignore"), "")
			writeFile(t, filepath.Join(repo, ".git", "config"), "x")
			writeFile(t, filepath.Join(repo, "app", "config.py"), "x")
		}, Evaluated, FailNone, []string{"app"}, []string{"app/config.py", "app/config.py"}, true},
		{"only the ignore file: nothing to start", func(t *testing.T, repo string) {
			writeFile(t, filepath.Join(repo, ".gitleaksignore"), "")
		}, Evaluated, FailNone, nil, nil, true},
		{"root link is never followed", func(t *testing.T, repo string) {
			writeFile(t, filepath.Join(repo, ".gitleaksignore"), "")
			outside := filepath.Join(filepath.Dir(repo), "outside")
			writeFile(t, filepath.Join(outside, "config.py"), "x")
			linkDir(t, outside, filepath.Join(repo, "link"))
		}, Evaluated, FailNone, nil, nil, true},
		{"a root directory with its own ignore file fails closed", func(t *testing.T, repo string) {
			writeFile(t, filepath.Join(repo, ".gitleaksignore"), "")
			writeFile(t, filepath.Join(repo, "app", ".gitleaksignore"), "app/config.py:generic-api-key:3\n")
		}, Failed, FailRepoIgnore, nil, nil, false},
		{"more root entries than the cap fail closed", func(t *testing.T, repo string) {
			writeFile(t, filepath.Join(repo, ".gitleaksignore"), "")
			for i := range maxGitleaksSources {
				writeFile(t, filepath.Join(repo, fmt.Sprintf("f%03d.txt", i)), "x")
			}
		}, Failed, FailRepoIgnore, nil, nil, false},
		{"a nested ignore file alone is not read: one run", func(t *testing.T, repo string) {
			writeFile(t, filepath.Join(repo, "app", ".gitleaksignore"), "")
		}, Evaluated, FailNone, []string{"."}, []string{"config.py", "config.py"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			repo := filepath.Join(base, "repo")
			mkdir(t, repo)
			tc.setup(t, repo)
			bin := installFake(t, base, "echo", "gitleaks")
			got := Run(context.Background(), Job{Scanner: repofile.ScannerGitleaks, Bin: bin, Repo: repo, Limits: testLimits()})
			if got.Outcome != tc.want || got.Failure != tc.failure || got.SkippedRepoIgnore != tc.skipped {
				t.Fatalf("Run = %+v, want outcome %d, failure %s, skipped %v", got, tc.want, tc.failure, tc.skipped)
			}
			if logged := relSources(t, repo, loggedSources(t, bin)); !slices.Equal(logged, tc.sources) {
				t.Errorf("sources %q, want %q", logged, tc.sources)
			}
			var paths []string
			for _, f := range got.Findings {
				paths = append(paths, f.Path)
			}
			slices.Sort(paths)
			if !slices.Equal(paths, tc.findings) {
				t.Errorf("findings %q, want %q", paths, tc.findings)
			}
		})
	}
}

func relSources(t *testing.T, repo string, sources []string) []string {
	t.Helper()
	var out []string
	for _, s := range sources {
		rel, err := filepath.Rel(repo, s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}

// linkDir makes link point at the directory target: a symbolic link, or
// on Windows without the symlink privilege a junction.
func linkDir(t *testing.T, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if runtime.GOOS != "windows" {
		t.Skipf("symlink: %v", err)
	}
	// mklink is a cmd built-in; the test, not the runner, uses the shell.
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil { //nolint:gosec // G204: test paths in t.TempDir()
		t.Skipf("mklink /J: %v: %s", err, out)
	}
}

func mkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}
