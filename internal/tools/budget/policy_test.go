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

// Every required phrase must be enforced on its own, not just some of them,
// and hiding it in markup GitHub does not render counts as removing it (#101).
func TestCheckPolicyEachPhrase(t *testing.T) {
	hiders := map[string]func(string) string{
		"comment":         func(p string) string { return "<!-- " + p + " -->" },
		"link definition": func(p string) string { return "[//]: # (" + p + ")" },
		"link title":      func(p string) string { return "[x]: <https://example.com>\n  \"" + p + "\"" },
	}
	for name, phrases := range requiredPolicy {
		for i, phrase := range phrases {
			for how, hide := range hiders {
				t.Run(name+"/"+how+"/"+phrase, func(t *testing.T) {
					root := writePolicy(t)
					rest := append(append([]string{}, phrases[:i]...), phrases[i+1:]...)
					writeFile(t, root, name, strings.Join(append(rest, hide(phrase)), "\n"))
					problems, err := checkPolicy(root, readPolicyFile)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(strings.Join(problems, "\n"), name) {
						t.Fatalf("hiding %q in %s was not reported: %v", phrase, name, problems)
					}
				})
			}
		}
	}
}

// policyReports writes content as name next to the other complete policy
// files and reports whether checkPolicy flags phrase in it.
func policyReports(t *testing.T, name, content, phrase string) bool {
	t.Helper()
	root := writePolicy(t)
	writeFile(t, root, name, content)
	problems, err := checkPolicy(root, readPolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(strings.Join(problems, "\n"), phrase)
}

// without returns name's required phrases joined by newlines, minus phrase.
func without(name, phrase string) string {
	var rest []string
	for _, p := range requiredPolicy[name] {
		if p != phrase {
			rest = append(rest, p)
		}
	}
	return strings.Join(rest, "\n")
}

// A link-reference definition hides its line and any title lines that
// follow, but nothing past the next blank line and nothing mid-line (#101).
func TestCheckPolicyHiddenByLinkDefinition(t *testing.T) {
	phrase := agentLoop
	tests := []struct {
		name    string
		content string
		missing bool
	}{
		{"visible", phrase, false},
		{"comment-style definition", "[//]: # (" + phrase + ")", true},
		{"no space after the colon", "[//]:# (" + phrase + ")", true},
		{"definition title", "[x]: <https://example.com> \"" + phrase + "\"", true},
		{"title on the next line", "[x]: https://example.com\n'" + phrase + "'", true},
		{"indented definition", "   [x]: # (" + phrase + ")", true},
		{"inside a blockquote", "> [x]: # (" + phrase + ")", true},
		{"escaped bracket in the label", `[a\]b]: # (` + phrase + ")", true},
		{"CRLF title line", "[x]: https://example.com\r\n\"" + phrase + "\"\r\n", true},
		{"after a blank line", "[x]: https://example.com\n\n" + phrase, false},
		{"after a CRLF blank line", "[x]: https://example.com\r\n\r\n" + phrase, false},
		{"bracket colon mid-line", "see [x]: " + phrase, false},
		{"inline link", "[x](https://example.com) " + phrase, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := without("AGENTS.md", phrase) + "\n\n" + tt.content
			if got := policyReports(t, "AGENTS.md", content, phrase); got != tt.missing {
				t.Fatalf("phrase reported missing = %v, want %v", got, tt.missing)
			}
		})
	}
}

// The template phrases count only as their own unindented checkbox line:
// moved into prose, a code block, another line or a ticked box, they fail (#101).
func TestCheckPolicyTemplateCheckboxLine(t *testing.T) {
	const name = ".github/PULL_REQUEST_TEMPLATE.md"
	bare := strings.TrimPrefix(templateSkip, checkbox)
	tests := []struct {
		name    string
		line    string
		missing bool
	}{
		{"checkbox line", templateSkip, false},
		{"trailing spaces", templateSkip + "  ", false},
		{"CRLF", templateSkip + "\r\n", false},
		{"followed by a comment", templateSkip + " <!-- note -->", false},
		{"in prose", "Note: " + bare, true},
		{"without the checkbox", bare, true},
		{"after other text on the line", "Note: " + templateSkip, true},
		{"indented as code", "    " + templateSkip, true},
		{"nested under another item", "  " + templateSkip, true},
		{"trailing clause added", templateSkip + " Not for this repository.", true},
		{"ticked", strings.Replace(templateSkip, "[ ]", "[x]", 1), true},
		{"split over two lines", strings.Replace(templateSkip, " Maintainer PRs:", "\nMaintainer PRs:", 1), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := without(name, templateSkip) + "\n" + tt.line
			if got := policyReports(t, name, content, "External contributor"); got != tt.missing {
				t.Fatalf("checkbox reported missing = %v, want %v", got, tt.missing)
			}
		})
	}
}

// Dropping the trailing clause of a pinned ADR 0002 sentence fails the
// guard, not only dropping the whole sentence (#101).
func TestCheckPolicyTrailingClause(t *testing.T) {
	tests := []struct {
		file, phrase, clause string
	}{
		{"AGENTS.md", auditorEscalation, " so the release pentest covers it"},
		{"CONTRIBUTING.md", auditorEscalation, " so the release pentest covers it"},
		{"AGENTS.md", sharedContext, " (issue, diff, test output, earlier verdicts)"},
		{"AGENTS.md", pentesterIsolation, ", so its review stays independent"},
		{"CONTRIBUTING.md", sharedContextShort, "."},
		{"CONTRIBUTING.md", pentesterIsolationNote, "."},
	}
	for _, tt := range tests {
		t.Run(tt.file+"/"+tt.clause, func(t *testing.T) {
			cut := strings.Replace(tt.phrase, tt.clause, "", 1)
			if cut == tt.phrase {
				t.Fatalf("%q is not in %q", tt.clause, tt.phrase)
			}
			content := without(tt.file, tt.phrase) + "\n" + cut + " only when asked"
			if !policyReports(t, tt.file, content, tt.file) {
				t.Fatalf("dropping %q from %s was not reported", tt.clause, tt.file)
			}
		})
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
