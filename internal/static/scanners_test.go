package static

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

func TestWithin(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	tests := []struct {
		path string
		want bool
	}{
		{root, true},
		{filepath.Join(root, "a", "b"), true},
		{filepath.Join(root, "..dots", "x"), true},
		{filepath.Join(root, "..", "repo2", "x"), false},
		{filepath.Dir(root), false},
	}
	for _, tc := range tests {
		if got := within(tc.path, root); got != tc.want {
			t.Errorf("within(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
