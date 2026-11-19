package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestVendorProofsExactCase (#213 tester L1): a mark counts only when its
// directory lists it spelled byte for byte and as a regular file, on every
// file system: PACKAGE.JSON or PyVenv.CFG prove nothing even where a stat
// of package.json would find them.
func TestVendorProofsExactCase(t *testing.T) {
	repo := t.TempDir()
	for _, name := range []string{
		"node_modules/upper/PACKAGE.JSON", "node_modules/ok/package.json",
		"node_modules/@s/ok/package.json", "venv/PyVenv.CFG", ".venv/pyvenv.cfg",
	} {
		writeTreeFile(t, repo, name, "{}")
	}
	if err := os.MkdirAll(filepath.Join(repo, "node_modules", "dir", "package.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(repo)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	tests := []struct {
		file string
		want bool
	}{
		{"node_modules/ok/index.js", true},
		{"node_modules/@s/ok/lib/i.ts", true},
		{".venv/lib/x.py", true},
		{"node_modules/upper/index.js", false},
		{"venv/lib/x.py", false},
		{"node_modules/dir/index.js", false}, // the mark is a directory
		{"node_modules/missing/index.js", false},
		{"node_modules/ok/x.py", false}, // package.json vouches only for JavaScript
	}
	proofs := newVendorProofs(root)
	for _, tt := range tests {
		for range 2 { // the second answer comes from the cache
			if got := proofs.proven(tt.file); got != tt.want {
				t.Errorf("proven(%q) = %v, want %v", tt.file, got, tt.want)
			}
		}
	}
}

func writeTreeFile(t *testing.T, repo, name, content string) {
	t.Helper()
	path := filepath.Join(repo, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
