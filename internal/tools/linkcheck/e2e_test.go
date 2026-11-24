package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// evilModule writes a main module (testMod) whose cmd/creep calls Run in a
// fake third-party module, github.com/evil/pkg, through a replace.
func evilModule(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod":            "module " + testMod + "\n\ngo 1.24\n\nrequire github.com/evil/pkg v0.0.0\n\nreplace github.com/evil/pkg => ./evil\n",
		"cmd/creep/main.go": "package main\n\nimport \"github.com/evil/pkg\"\n\nfunc main() { pkg.Run() }\n",
		"evil/go.mod":       "module github.com/evil/pkg\n\ngo 1.24\n",
		"evil/pkg.go":       "package pkg\n\n" + body,
	}
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// Protection (v0.3 tester T1): the check runs on a real link of every
// release OS. A small function is inlined into its caller, and a syscall
// wrapper into the third-party code calling it, so with inlining the
// linker charges the edge to creep's own code or to a lower-case wrapper.
// Each row must still be caught; the clean row proves the walk passes
// harmless third-party code.
func TestRealLinkCatchesInlinedCalls(t *testing.T) {
	if testing.Short() {
		t.Skip("links a fake module for three OSes")
	}
	tests := []struct {
		name, body, want string // want "" for no problem
	}{
		{"socket", "import \"syscall\"\n\nfunc Run() { _, _ = syscall.Socket(2, 1, 0) }\n", "syscall."},
		{"inlined dial", "import \"net\"\n\nfunc Run() { _, _ = net.Dial(\"tcp\", \"127.0.0.1:1\") }\n", "net.Dial"},
		{"harmless", "import \"strings\"\n\nvar Out string\n\nfunc Run() { Out = strings.ToUpper(Out) }\n", ""},
	}
	for _, tt := range tests {
		root := evilModule(t, tt.body)
		for _, goos := range []string{"linux", "darwin", "windows"} {
			t.Run(tt.name+"/"+goos, func(t *testing.T) {
				g, err := dumpLinkGraph(root, target{goos, "amd64"}, filepath.Join(t.TempDir(), "creep"))
				if err != nil {
					t.Fatal(err)
				}
				got := strings.Join(checkLinkReach(testMod, g, map[string]bool{}), "\n")
				if tt.want == "" && got != "" {
					t.Errorf("false positive: %s", got)
				}
				if tt.want != "" && !strings.Contains(got, "github.com/evil/pkg.Run -> "+tt.want) {
					t.Errorf("got %q, want an edge from github.com/evil/pkg.Run to %s", got, tt.want)
				}
			})
		}
	}
}
