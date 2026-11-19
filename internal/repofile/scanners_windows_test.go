//go:build windows

package repofile

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestDetectScannersVerbatimPath covers the \\?\ case from PR #218: a
// verbatim PATH entry into the repository is refused, and one outside it
// is found with a final path that has no verbatim prefix. Junctions need
// mklink, so their case lives with the runner (internal/scanrun).
func TestDetectScannersVerbatimPath(t *testing.T) {
	bin, repo := t.TempDir(), t.TempDir()
	fakeBinary(t, filepath.Join(repo, "bin"), "gitleaks", 0o755)
	fakeBinary(t, bin, "osv-scanner", 0o755)
	tests := []struct {
		name, path string
		want       ScannerState
	}{
		{"verbatim entry into the repository", `\\?\` + filepath.Join(repo, "bin"), ScannerRefused},
		{"verbatim entry into the repository, upper case", `\\?\` + strings.ToUpper(filepath.Join(repo, "bin")), ScannerRefused},
		{"forward slashes into the repository", filepath.ToSlash(filepath.Join(repo, "bin")), ScannerRefused},
		{"verbatim entry outside", `\\?\` + bin, ScannerFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectScanners([]string{"gitleaks", "osv-scanner"}, ScannerEnv{Path: tc.path, Repo: repo})
			state, path := got[0].State, got[0].Path
			if tc.want == ScannerFound {
				state, path = got[1].State, got[1].Path
			}
			if state != tc.want {
				t.Fatalf("state = %d, want %d", state, tc.want)
			}
			if strings.HasPrefix(path, `\\?\`) {
				t.Errorf("final path %q keeps the verbatim prefix", path)
			}
		})
	}
}

func TestStripVerbatim(t *testing.T) {
	tests := map[string]string{
		`\\?\C:\x\y`:          `C:\x\y`,
		`\??\C:\x`:            `C:\x`,
		`\\?\UNC\srv\share\x`: `\\srv\share\x`,
		`\\?\unc\srv\share`:   `\\srv\share`,
		`C:\plain`:            `C:\plain`,
		`\\?\Volume{0000}\x`:  `Volume{0000}\x`,
	}
	for in, want := range tests {
		if got := stripVerbatim(in); got != want {
			t.Errorf("stripVerbatim(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := finalPath(`\\?\Volume{00000000-0000-0000-0000-000000000000}\x`); err == nil {
		t.Error("a volume GUID path must fail closed")
	}
}
