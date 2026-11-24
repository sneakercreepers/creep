package main

import (
	"regexp"
	"strings"
	"testing"
)

// skipWhenDocsOnly is the job condition that skips a heavy job on a
// docs-only pull request and runs it when the changes job failed.
const skipWhenDocsOnly = "    needs: changes\n    if: ${{ !cancelled() && needs.changes.outputs.docs_only != 'true' }}\n" //nolint:misspell // cancelled() is the GitHub Actions function name

// jobKey matches a top-level job key line.
var jobKey = regexp.MustCompile(`\n  [A-Za-z0-9_-]+:\n`)

// jobBlock returns the text of a top-level job, from its key to the next job.
func jobBlock(t *testing.T, wf, name string) string {
	t.Helper()
	start := strings.Index(wf, "\n  "+name+":\n")
	if start < 0 {
		t.Fatalf("no job %q", name)
	}
	rest := wf[start+1:]
	if loc := jobKey.FindStringIndex(rest); loc != nil {
		return rest[:loc[0]+1]
	}
	return rest
}

// The docs-only skip must classify with the base commit's prcheck, only on
// pull requests, and must never leave a required check pending or skip a
// push to main (ADR 0018 amendment, 2026-11-23).
func TestDocsOnlySkipWiring(t *testing.T) {
	changes := readRepoFile(t, ".github/workflows/changes.yml")
	for _, want := range []string{
		"  workflow_call:\n",
		`git worktree add --detach "$RUNNER_TEMP/base" HEAD^1`,
		"working-directory: ${{ runner.temp }}/base",
		`go run ./internal/tools/prcheck -ci-scope -files "$RUNNER_TEMP/changed" >> "$GITHUB_OUTPUT"`,
		"        if: github.event_name == 'pull_request'\n        continue-on-error: true\n",
	} {
		if !strings.Contains(changes, want) {
			t.Errorf("changes.yml lacks %q", want)
		}
	}
	ci := readRepoFile(t, ".github/workflows/ci.yml")
	codeql := readRepoFile(t, ".github/workflows/codeql.yml")
	for _, wf := range []string{ci, codeql} {
		if strings.Contains(wf, "paths-ignore") || strings.Contains(wf, "paths:") {
			t.Error("a path filter leaves required checks pending; use the changes job")
		}
		// The pull request's head must not supply its own classifier (L3).
		if !strings.Contains(jobBlock(t, wf, "changes"), "    uses: sneakercreepers/creep/.github/workflows/changes.yml@main ") {
			t.Error("the changes job must run changes.yml from main, not ./ from the pull request's head")
		}
	}
	if !ciSkippable("docs/x.md") || ciSkippable(".github/workflows/changes.yml") || ciSkippable(".github/CODEOWNERS") {
		t.Error("only prose may skip; any .github/ change must run everything")
	}
	if !strings.Contains(ci, "  push:\n    branches: [main]\n") {
		t.Error("ci.yml must run on every push to main")
	}
	for _, job := range []string{"lint", "vuln", "workflows", "budget", "protections", "action"} {
		if !strings.Contains(jobBlock(t, ci, job), skipWhenDocsOnly) {
			t.Errorf("ci.yml job %s lacks the docs-only condition %q", job, skipWhenDocsOnly)
		}
	}
	for _, job := range []string{"secrets", "dependency-review"} {
		if strings.Contains(jobBlock(t, ci, job), "docs_only") {
			t.Errorf("ci.yml job %s must run on docs-only pull requests too", job)
		}
	}
	if !strings.Contains(jobBlock(t, codeql, "analyze"), skipWhenDocsOnly) {
		t.Errorf("codeql.yml analyze lacks %q", skipWhenDocsOnly)
	}
	test := jobBlock(t, ci, "test")
	if !strings.Contains(test, "    needs: changes\n    if: ${{ !cancelled() }}\n") { //nolint:misspell // cancelled() is the GitHub Actions function name
		t.Error("the test matrix must run its job and skip only its steps: a skipped matrix job reports no check under its expanded name")
	}
	if n := strings.Count(test, "      - "); strings.Count(test, "docs_only") != n {
		t.Errorf("every one of the %d test steps must test docs_only", n)
	}
}
