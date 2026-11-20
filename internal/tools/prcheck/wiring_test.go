package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const repoRoot = "../../.."

func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

// The check is only a gate when CI runs it on body edits, lists renames as
// both paths, and the main ruleset requires the job.
func TestPRBodyJobIsRequired(t *testing.T) {
	wf := readRepoFile(t, ".github/workflows/pr.yml")
	for _, want := range []string{
		"types: [opened, edited, reopened, synchronize]",
		"\n  pr-body:\n",
		"git diff --no-renames --name-only -z HEAD^1 HEAD",
		`go run ./internal/tools/prcheck -event "$GITHUB_EVENT_PATH" -files`,
	} {
		if !strings.Contains(wf, want) {
			t.Errorf(".github/workflows/pr.yml lacks %q", want)
		}
	}
	var rs struct {
		Rules []struct {
			Type       string `json:"type"`
			Parameters struct {
				Checks []struct{ Context string } `json:"required_status_checks"`
			} `json:"parameters"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, ".github/rulesets/main.json")), &rs); err != nil {
		t.Fatal(err)
	}
	for _, r := range rs.Rules {
		for _, c := range r.Parameters.Checks {
			if r.Type == "required_status_checks" && c.Context == "pr-body" {
				return
			}
		}
	}
	t.Error(".github/rulesets/main.json: pr-body is not a required status check")
}

// The classification must say what AGENTS.md says: when its docs-only rule
// changes, this test points at policyNames and docsOnlyReason.
func TestDocsOnlyMatchesAgents(t *testing.T) {
	var rule string
	for _, line := range strings.Split(readRepoFile(t, "AGENTS.md"), "\n") {
		if strings.Contains(line, "Documentation-only changes run only the auditor") {
			rule = line
		}
	}
	for _, want := range []string{"only `*.md` files or `docs/`", "not code, workflows, settings, Makefile or the policy files (AGENTS.md, CLAUDE.md, CONTRIBUTING.md, PR template)"} {
		if !strings.Contains(rule, want) {
			t.Errorf("AGENTS.md docs-only rule changed (lacks %q): update prcheck to match", want)
		}
	}
	if len(policyNames) != 4 {
		t.Errorf("policyNames has %d entries, AGENTS.md names 4 policy files", len(policyNames))
	}
}

// Each loop box of the PR template, once ticked, must be the box prcheck
// checks; rewording the template must not turn the check off.
func TestTemplateBoxesAreRecognized(t *testing.T) {
	template := readRepoFile(t, ".github/PULL_REQUEST_TEMPLATE.md")
	want := map[box]bool{loopBox: false, externalBox: false, docsBox: false}
	for _, line := range strings.Split(template, "\n") {
		if !strings.HasPrefix(line, "- [ ] ") {
			continue
		}
		for b := range tickedItems(strings.Replace(line, "[ ]", "[x]", 1)) {
			if _, ok := want[b]; ok {
				want[b] = true
			}
		}
	}
	for b, seen := range want {
		if !seen {
			t.Errorf("no PR template box is recognized as box %d", b)
		}
	}
}
