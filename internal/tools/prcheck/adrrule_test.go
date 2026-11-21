package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsPolicyPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"CLAUDE.md", true},
		{"CONTRIBUTING.md", true},
		{".github/PULL_REQUEST_TEMPLATE.md", true},
		{".github/PULL_REQUEST_TEMPLATE/security.md", true},
		{"docs/pull_request_template.md", true},
		{"internal/gateway/CLAUDE.md", true},
		{"docs/agents.md", true},
		{"internal/tools/budget/policy.go", true},
		{"internal/tools/budget/policy_test.go", true},
		{"Internal/Tools/Budget/Policy.go", true},
		{"internal/tools/prcheck/main.go", true},
		{"internal/tools/prcheck/testdata/x.json", true},
		{"docs/adr/0002-agent-loop-scope.md", true},
		{"docs/adr/0018-docs-only-exclusions.md", true},
		{"AGENTS.md", true}, // policyChanges compares the root one by its loop section first
		{"README.md", false},
		{"Makefile", false},
		{"internal/tools/budget/main.go", false},
		{"internal/tools/budget/policy.txt", false},
		{"internal/tools/budget/nested/policy.go", false},
		{"internal/tools/prcheckx/main.go", false},
		{"docs/adr/0003-architecture-layers.md", false},
		{"docs/adr/0020-x.md", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isPolicyPath(tt.path); got != tt.want {
				t.Fatalf("isPolicyPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

const loopChanged = "# AGENTS.md\n\n" + loopHeading + "\n\n- developer → auditor\n\n## Current state\n\n- v0.1\n"

func TestADRProblems(t *testing.T) {
	stateOnly := strings.Replace(baseAgentsText, "- v0.1", "- v0.2", 1)
	tests := []struct {
		name  string
		files []string
		head  string   // AGENTS.md in the tree; "" deletes it
		tree  []string // other files present after the change
		want  string   // "" means no problem
	}{
		{"no policy change", []string{"README.md", "Makefile"}, baseAgentsText, nil, ""},
		{"policy file without an ADR", []string{"CONTRIBUTING.md"}, baseAgentsText, nil, `"CONTRIBUTING.md" changes the agent-loop policy`},
		{"policy guard without an ADR", []string{"internal/tools/budget/policy.go"}, baseAgentsText, nil, `"internal/tools/budget/policy.go"`},
		{"prcheck without an ADR", []string{"internal/tools/prcheck/adrrule.go"}, baseAgentsText, nil, `"internal/tools/prcheck/adrrule.go"`},
		{"policy file with a new ADR", []string{"CONTRIBUTING.md", "docs/adr/0019-x.md"}, baseAgentsText, []string{"docs/adr/0019-x.md"}, ""},
		{"policy ADR amended", []string{"docs/adr/0018-docs-only-exclusions.md"}, baseAgentsText, []string{"docs/adr/0018-docs-only-exclusions.md"}, ""},
		{"ADR deleted", []string{"CLAUDE.md", "docs/adr/0019-x.md"}, baseAgentsText, nil, `"CLAUDE.md"`},
		{"only the ADR template", []string{"CLAUDE.md", "docs/adr/0000-template.md"}, baseAgentsText, []string{"docs/adr/0000-template.md"}, `"CLAUDE.md"`},
		{"only the dependency allowlist", []string{"CLAUDE.md", "docs/adr/dependencies.txt"}, baseAgentsText, []string{"docs/adr/dependencies.txt"}, `"CLAUDE.md"`},
		{"ADR in a subfolder", []string{"CLAUDE.md", "docs/adr/old/0019-x.md"}, baseAgentsText, []string{"docs/adr/old/0019-x.md"}, `"CLAUDE.md"`},
		{"ADR in another case", []string{"CLAUDE.md", "Docs/ADR/0019-x.md"}, baseAgentsText, []string{"Docs/ADR/0019-x.md"}, `"CLAUDE.md"`},
		{"AGENTS.md current state only", []string{"AGENTS.md"}, stateOnly, nil, ""},
		{"AGENTS.md line endings only", []string{"AGENTS.md"}, strings.ReplaceAll(baseAgentsText, "\n", "\r\n"), nil, ""},
		{"AGENTS.md loop changed", []string{"AGENTS.md"}, loopChanged, nil, "agent-loop section"},
		{"AGENTS.md loop changed with an ADR", []string{"AGENTS.md", "docs/adr/0019-x.md"}, loopChanged, []string{"docs/adr/0019-x.md"}, ""},
		{"AGENTS.md loop heading renamed", []string{"AGENTS.md"}, strings.Replace(baseAgentsText, loopHeading, "## Workflow", 1), nil, "agent-loop section"},
		{"AGENTS.md loop heading repeated", []string{"AGENTS.md"}, baseAgentsText + loopHeading + "\n", nil, "agent-loop section"},
		{"AGENTS.md heading planted in the loop", []string{"AGENTS.md"}, strings.Replace(baseAgentsText, "- developer", "## Note\n- developer", 1), nil, "agent-loop section"},
		{"AGENTS.md deleted", []string{"AGENTS.md"}, "", nil, "agent-loop section"},
		{"AGENTS.md changed but not listed", []string{"README.md"}, loopChanged, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "docs", "adr"), 0o750); err != nil {
				t.Fatal(err)
			}
			if tt.head != "" {
				writeTree(t, root, rootAgents, tt.head)
			}
			for _, f := range tt.tree {
				writeTree(t, root, f, "x")
			}
			problems, err := adrProblems(tt.files, root, baseAgentsText)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(problems, "\n")
			if tt.want == "" && got != "" {
				t.Fatalf("unexpected problems: %s", got)
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("problems %q do not contain %q", got, tt.want)
			}
		})
	}
}

// The base AGENTS.md must hold exactly one loop heading too: otherwise the
// comparison has no anchor and counts as a change.
func TestADRProblemsBaseWithoutLoop(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, rootAgents, baseAgentsText)
	problems, err := adrProblems([]string{rootAgents}, root, "# AGENTS.md\n")
	if err != nil || len(problems) != 1 {
		t.Fatalf("problems %v, err %v; want one", problems, err)
	}
}

// A symlinked ADR, or a symlinked docs/adr/, does not vouch for a policy
// change: it could point at a record the PR deleted.
func TestHasADRRejectsSymlinks(t *testing.T) {
	tests := []struct {
		name string
		link func(root, elsewhere string) error
	}{
		{"file", func(root, elsewhere string) error {
			return os.Symlink(filepath.Join(elsewhere, "docs", "adr", "0019-x.md"), filepath.Join(root, "docs", "adr", "0019-x.md"))
		}},
		{"directory", func(root, elsewhere string) error {
			if err := os.RemoveAll(filepath.Join(root, "docs", "adr")); err != nil {
				return err
			}
			return os.Symlink(filepath.Join(elsewhere, "docs", "adr"), filepath.Join(root, "docs", "adr"))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, elsewhere := t.TempDir(), t.TempDir()
			writeTree(t, root, "docs/adr/0001-a.md", "x")
			writeTree(t, elsewhere, "docs/adr/0019-x.md", "x")
			if err := tt.link(root, elsewhere); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if hasADR([]string{"docs/adr/0019-x.md"}, root) {
				t.Fatal("a symlinked ADR path must not count")
			}
		})
	}
}
