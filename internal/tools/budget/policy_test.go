package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePolicy creates every policy file with all required phrases under a temp root.
func writePolicy(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, phrases := range requiredPolicy {
		writeFile(t, root, name, strings.Join(phrases, "\n"))
	}
	return root
}

func writeFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCheckPolicyComplete(t *testing.T) {
	problems, err := checkPolicy(writePolicy(t), readPolicyFile)
	if err != nil || len(problems) > 0 {
		t.Fatalf("problems %v, err %v", problems, err)
	}
}

// Every required phrase must be enforced on its own, not just some of them.
func TestCheckPolicyEachPhrase(t *testing.T) {
	for name, phrases := range requiredPolicy {
		for i, phrase := range phrases {
			t.Run(name+"/"+phrase, func(t *testing.T) {
				root := writePolicy(t)
				rest := append(append([]string{}, phrases[:i]...), phrases[i+1:]...)
				hidden := "<!-- " + phrase + " -->"
				writeFile(t, root, name, strings.Join(append(rest, hidden), "\n"))
				problems, err := checkPolicy(root, readPolicyFile)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(strings.Join(problems, "\n"), name) {
					t.Fatalf("removing %q from %s was not reported: %v", phrase, name, problems)
				}
			})
		}
	}
}

func TestCheckPolicyMissingFile(t *testing.T) {
	root := writePolicy(t)
	if err := os.Remove(filepath.Join(root, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	problems, err := checkPolicy(root, readPolicyFile)
	if err != nil || !strings.Contains(strings.Join(problems, "\n"), "AGENTS.md is missing") {
		t.Fatalf("problems %v, err %v", problems, err)
	}
}

func TestCheckPolicyReadErrorFailsClosed(t *testing.T) {
	failing := func(string, string) ([]byte, error) { return nil, errors.New("boom") }
	if _, err := checkPolicy(writePolicy(t), failing); err == nil {
		t.Fatal("read error must fail the budget")
	}
}

// A <!-- with no closing tag hides the rest of the file, so a phrase after it
// is missing; a closed comment before the phrase still leaves it visible (#58).
func TestCheckPolicyHiddenByComment(t *testing.T) {
	phrase := requiredPolicy["AGENTS.md"][0]
	tests := []struct {
		name    string
		content string
		missing bool
	}{
		{"visible", phrase, false},
		{"after a closed comment", "<!-- note -->\n" + phrase, false},
		{"inside a closed comment", "<!-- " + phrase + " -->", true},
		{"after an unclosed comment", "<!-- note\n" + phrase, true},
		{"after a closed then an unclosed comment", "<!-- a --> <!-- b\n" + phrase, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writePolicy(t)
			rest := strings.Join(requiredPolicy["AGENTS.md"][1:], "\n")
			writeFile(t, root, "AGENTS.md", rest+"\n"+tt.content)
			problems, err := checkPolicy(root, readPolicyFile)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Contains(strings.Join(problems, "\n"), phrase)
			if got != tt.missing {
				t.Fatalf("phrase reported missing = %v, want %v (problems %v)", got, tt.missing, problems)
			}
		})
	}
}

// A symlink anywhere below the root, the file or a parent directory, fails
// the budget instead of reading what it points at (#58).
func TestReadPolicyFileRejectsSymlinks(t *testing.T) {
	tests := []struct {
		name string
		link func(t *testing.T, root, elsewhere string) error
	}{
		{"file", func(t *testing.T, root, elsewhere string) error {
			target := filepath.Join(elsewhere, ".github", "PULL_REQUEST_TEMPLATE.md")
			path := filepath.Join(root, ".github", "PULL_REQUEST_TEMPLATE.md")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			return os.Symlink(target, path)
		}},
		{"parent directory", func(t *testing.T, root, elsewhere string) error {
			if err := os.RemoveAll(filepath.Join(root, ".github")); err != nil {
				t.Fatal(err)
			}
			return os.Symlink(filepath.Join(elsewhere, ".github"), filepath.Join(root, ".github"))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, elsewhere := writePolicy(t), writePolicy(t)
			if err := tt.link(t, root, elsewhere); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if _, err := checkPolicy(root, readPolicyFile); err == nil {
				t.Fatal("a symlinked policy path must fail the budget")
			}
		})
	}
}

func TestReadPolicyFileRejectsNonRegular(t *testing.T) {
	root := writePolicy(t)
	if err := os.MkdirAll(filepath.Join(root, "dir.md"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyFile(root, "dir.md"); err == nil {
		t.Fatal("a directory must be rejected")
	}
	if _, err := readPolicyFile(root, ".github/PULL_REQUEST_TEMPLATE.md"); err != nil {
		t.Fatalf("a regular file under plain directories: %v", err)
	}
}
