package repofile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeBinary writes a file the OS would treat as the named program. It is
// never run: detection only looks.
func fakeBinary(t *testing.T, dir, name string, mode os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("not a program\n"), mode); err != nil {
		t.Fatal(err)
	}
}

func pathList(dirs ...string) string { return strings.Join(dirs, string(os.PathListSeparator)) }

func TestDetectScanners(t *testing.T) {
	all := []string{"gitleaks", "osv-scanner", "semgrep"}
	tests := []struct {
		name    string
		enabled []string
		setup   func(t *testing.T, bin, repo string) string // returns PATH
		want    ScannerState
	}{
		{"not enabled though installed", nil, func(t *testing.T, bin, _ string) string {
			fakeBinary(t, bin, "semgrep", 0o755)
			return bin
		}, ScannerNotEnabled},
		{"absent", all, func(_ *testing.T, bin, _ string) string { return bin }, ScannerMissing},
		{"empty PATH", all, func(*testing.T, string, string) string { return "" }, ScannerMissing},
		{"present outside the repository", all, func(t *testing.T, bin, _ string) string {
			fakeBinary(t, bin, "semgrep", 0o755)
			return bin
		}, ScannerFound},
		{"present inside the repository is refused", all, func(t *testing.T, bin, repo string) string {
			fakeBinary(t, filepath.Join(repo, "tools"), "semgrep", 0o755)
			return filepath.Join(repo, "tools")
		}, ScannerRefused},
		{"repository first on PATH wins over a real install", all, func(t *testing.T, bin, repo string) string {
			fakeBinary(t, bin, "semgrep", 0o755)
			fakeBinary(t, filepath.Join(repo, "node_modules", ".bin"), "semgrep", 0o755)
			return pathList(filepath.Join(repo, "node_modules", ".bin"), bin)
		}, ScannerRefused},
		{"relative PATH entry is refused", all, func(t *testing.T, _, repo string) string {
			fakeBinary(t, filepath.Join(repo, "bin"), "semgrep", 0o755)
			t.Chdir(repo)
			return "bin"
		}, ScannerRefused},
		{"empty PATH entry is the current directory, refused", all, func(t *testing.T, bin, repo string) string {
			fakeBinary(t, repo, "semgrep", 0o755)
			t.Chdir(repo)
			return pathList("", bin)
		}, ScannerRefused},
		{"a directory with the tool's name is not a binary", all, func(t *testing.T, bin, _ string) string {
			name := "semgrep"
			if runtime.GOOS == "windows" {
				name += ".exe"
			}
			if err := os.MkdirAll(filepath.Join(bin, name), 0o700); err != nil {
				t.Fatal(err)
			}
			return bin
		}, ScannerMissing},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bin, repo := t.TempDir(), t.TempDir()
			env := ScannerEnv{Path: tc.setup(t, bin, repo), Repo: repo}
			got := DetectScanners(tc.enabled, env)
			if len(got) != len(Scanners()) {
				t.Fatalf("got %d checks, want one per scanner", len(got))
			}
			if s := got[2]; s.Scanner != ScannerSemgrep || s.State != tc.want {
				t.Errorf("semgrep = %+v, want state %d", s, tc.want)
			}
			if s := got[2]; (s.State == ScannerFound) != filepath.IsAbs(s.Path) {
				t.Errorf("semgrep path %q with state %d: only a found binary has a final path", s.Path, s.State)
			}
		})
	}
}

// TestDetectScannersUnixRules covers what only a Unix PATH search does:
// a file without an execute bit is skipped, and a link from outside into
// the repository is refused.
func TestDetectScannersUnixRules(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("execute bits and unprivileged symlinks are Unix only")
	}
	bin, repo := t.TempDir(), t.TempDir()
	fakeBinary(t, bin, "gitleaks", 0o644)
	fakeBinary(t, repo, "semgrep-real", 0o755)
	if err := os.Symlink(filepath.Join(repo, "semgrep-real"), filepath.Join(bin, "semgrep")); err != nil {
		t.Fatal(err)
	}
	got := DetectScanners([]string{"gitleaks", "semgrep"}, ScannerEnv{Path: bin, Repo: repo})
	want := []ScannerState{ScannerMissing, ScannerNotEnabled, ScannerRefused}
	for i, w := range want {
		if got[i].State != w {
			t.Errorf("%s = %d, want %d", got[i].Scanner, got[i].State, w)
		}
	}
}

func TestDetectScannersFailsClosedWithoutRepo(t *testing.T) {
	bin := t.TempDir()
	fakeBinary(t, bin, "osv-scanner", 0o755)
	for _, repo := range []string{"", "relative/repo"} {
		got := DetectScanners([]string{"osv-scanner"}, ScannerEnv{Path: bin, Repo: repo})
		if got[1].State != ScannerRefused {
			t.Errorf("repo %q: osv-scanner = %d, want refused", repo, got[1].State)
		}
	}
}

// TestOutsideRepo covers the final-path refusal every runner relies on:
// the binary and each directory above it are compared with the repository
// by file identity, so look-alike names never pass and a sibling does.
func TestOutsideRepo(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	fakeBinary(t, filepath.Join(repo, "a", "b"), "tool", 0o755)
	fakeBinary(t, filepath.Join(base, "repo2"), "tool", 0o755)
	fakeBinary(t, filepath.Join(repo, "..dots"), "tool", 0o755)
	exe := func(dir string) string {
		if runtime.GOOS == "windows" {
			return filepath.Join(dir, "tool.exe")
		}
		return filepath.Join(dir, "tool")
	}
	tests := []struct {
		name, bin, repo string
		want            bool
	}{
		{"deep inside", exe(filepath.Join(repo, "a", "b")), repo, false},
		{"dotted directory inside", exe(filepath.Join(repo, "..dots")), repo, false},
		{"through .. back into the repository", exe(filepath.Join(base, "repo2", "..", "repo", "a", "b")), repo, false},
		{"sibling with a shared prefix", exe(filepath.Join(base, "repo2")), repo, true},
		// The same directory where names fold case; a missing one fails closed elsewhere.
		{"upper-case repository path", exe(filepath.Join(repo, "a", "b")), strings.ToUpper(repo), false},
		{"missing binary fails closed", exe(filepath.Join(base, "none")), repo, false},
		{"relative binary fails closed", "tool", repo, false},
		{"relative repository fails closed", exe(filepath.Join(base, "repo2")), "repo", false},
		{"empty repository fails closed", exe(filepath.Join(base, "repo2")), "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			final, ok := OutsideRepo(tc.bin, tc.repo)
			if ok != tc.want {
				t.Fatalf("OutsideRepo(%q, %q) = %q, %v; want %v", tc.bin, tc.repo, final, ok, tc.want)
			}
			if ok && !filepath.IsAbs(final) {
				t.Errorf("final path %q is not absolute", final)
			}
		})
	}
}

// TestOutsideRepoLinks covers links on every OS that allows unprivileged
// ones: a link from outside into the repository, a link to a link, a
// relative link and a cycle are resolved or refused.
func TestOutsideRepoLinks(t *testing.T) {
	base := t.TempDir()
	repo, out := filepath.Join(base, "repo"), filepath.Join(base, "out")
	fakeBinary(t, filepath.Join(repo, "bin"), "tool", 0o755)
	fakeBinary(t, out, "real", 0o755)
	name := "tool"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	symlink(t, filepath.Join(repo, "bin"), filepath.Join(out, "dirlink"))
	symlink(t, filepath.Join(out, "dirlink"), filepath.Join(out, "linklink"))
	symlink(t, filepath.Join("..", "repo", "bin"), filepath.Join(out, "rel"))
	symlink(t, filepath.Join(out, "loop1"), filepath.Join(out, "loop2"))
	symlink(t, filepath.Join(out, "loop2"), filepath.Join(out, "loop1"))
	for _, bin := range []string{
		filepath.Join(out, "dirlink", name),
		filepath.Join(out, "linklink", name),
		filepath.Join(out, "rel", name),
		filepath.Join(out, "loop1", name),
	} {
		if final, ok := OutsideRepo(bin, repo); ok {
			t.Errorf("OutsideRepo(%q) = %q, true; want refused", bin, final)
		}
	}
}

// symlink makes a link or skips the test where the OS refuses it (Windows
// without developer mode).
func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
}
