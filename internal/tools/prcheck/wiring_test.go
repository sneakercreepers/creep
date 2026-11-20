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
// both paths, keeps a read-only job, and the main ruleset requires it.
func TestDocsOnlyJobIsRequired(t *testing.T) {
	wf := readRepoFile(t, ".github/workflows/pr.yml")
	for _, want := range []string{
		"types: [opened, edited, reopened, synchronize]",
		"\npermissions: {}\n",
		"\n  docs-only:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n",
		"persist-credentials: false",
		"git diff --no-renames --name-only -z HEAD^1 HEAD",
		`go run ./internal/tools/prcheck -event "$GITHUB_EVENT_PATH" -files`,
	} {
		if !strings.Contains(wf, want) {
			t.Errorf(".github/workflows/pr.yml lacks %q", want)
		}
	}
	if !requiredCheck(t, "docs-only") {
		t.Error(".github/rulesets/main.json: docs-only is not a required status check")
	}
}

func requiredCheck(t *testing.T, context string) bool {
	t.Helper()
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
			if r.Type == "required_status_checks" && c.Context == context {
				return true
			}
		}
	}
	return false
}

// The classification must say what AGENTS.md says: when its docs-only rule
// changes, this test points at policyNames, settingsFiles and docsOnlyReason.
func TestDocsOnlyMatchesAgents(t *testing.T) {
	var rule string
	for _, line := range strings.Split(readRepoFile(t, "AGENTS.md"), "\n") {
		if strings.Contains(line, "Documentation-only changes run only the auditor") {
			rule = line
		}
	}
	for _, want := range []string{
		"only `*.md` files or `docs/`",
		"not code, workflows, settings (including `docs/adr/dependencies.txt`, which `make budget` reads), Makefile or the policy files (AGENTS.md, CLAUDE.md, CONTRIBUTING.md, PR template)",
		"The required `docs-only` CI check",
	} {
		if !strings.Contains(rule, want) {
			t.Errorf("AGENTS.md docs-only rule changed (lacks %q): update prcheck to match", want)
		}
	}
	if len(policyNames) != 4 {
		t.Errorf("policyNames has %d entries, AGENTS.md names 4 policy files", len(policyNames))
	}
	if len(settingsFiles) != 1 || !settingsFiles["docs/adr/dependencies.txt"] {
		t.Errorf("settingsFiles %v differs from the one file AGENTS.md names", settingsFiles)
	}
}

// The template's Documentation-only box, once ticked, must be the box
// prcheck looks for; rewording the template must not turn the check off.
func TestTemplateBoxIsRecognized(t *testing.T) {
	for _, line := range strings.Split(readRepoFile(t, ".github/PULL_REQUEST_TEMPLATE.md"), "\n") {
		if strings.HasPrefix(line, "- [ ] ") && docsOnlyClaimed(strings.Replace(line, "[ ]", "[x]", 1)) {
			return
		}
	}
	t.Error("no PR template box is recognized as the Documentation-only box")
}
