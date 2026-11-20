package main

import (
	"fmt"
	"path"
	"strings"
)

// policyNames are the policy files AGENTS.md keeps out of the docs-only
// shortcut, lowercase. They match at any depth because agents also read a
// nested AGENTS.md or CLAUDE.md, and GitHub reads a PR template from the
// root, docs/ or .github/ in any case.
var policyNames = map[string]bool{
	"agents.md":                true,
	"claude.md":                true,
	"contributing.md":          true,
	"pull_request_template.md": true,
}

// policyDir holds GitHub's multiple PR templates.
const policyDir = "pull_request_template"

// buildNames are code or build files that can sit under docs/, lowercase.
var buildNames = map[string]bool{
	"makefile":    true,
	"gnumakefile": true,
	"go.mod":      true,
	"go.sum":      true,
	"go.work":     true,
	"action.yml":  true,
	"action.yaml": true,
}

// settingsDirs hold workflows, rulesets, repository and agent settings.
var settingsDirs = []string{".github/", ".claude/"}

// settingsFiles sit under docs/ but are settings: make budget reads the
// dependency allowlist that backs invariant 6.
var settingsFiles = map[string]bool{"docs/adr/dependencies.txt": true}

// docsOnlyReason says why a changed path is outside the docs-only shortcut,
// or returns "" when it fits: only *.md or docs/, and not code, workflows,
// settings, a Makefile or a policy file.
func docsOnlyReason(p string) string {
	lower := strings.ToLower(p)
	if policyNames[path.Base(lower)] || hasDir(lower, policyDir) {
		return "a policy file"
	}
	if settingsFiles[lower] {
		return "a setting make budget reads"
	}
	for _, dir := range settingsDirs {
		if strings.HasPrefix(lower, dir) {
			return "workflows or settings"
		}
	}
	if buildNames[path.Base(lower)] || strings.HasSuffix(lower, ".mk") || strings.HasSuffix(lower, ".go") {
		return "code or a build file"
	}
	if strings.HasSuffix(lower, ".md") || strings.HasPrefix(p, "docs/") {
		return ""
	}
	return "neither *.md nor under docs/"
}

func hasDir(p, dir string) bool {
	parts := strings.Split(p, "/")
	for _, part := range parts[:len(parts)-1] {
		if part == dir {
			return true
		}
	}
	return false
}

// docsOnlyProblems reports each changed path the docs-only shortcut cannot
// cover. An empty list fails too: the shortcut needs files to vouch for.
func docsOnlyProblems(files []string) []string {
	if len(files) == 0 {
		return []string{"the Documentation-only box is ticked but no changed file was listed"}
	}
	var problems []string
	for _, f := range files {
		if reason := docsOnlyReason(f); reason != "" {
			problems = append(problems, fmt.Sprintf("the Documentation-only box is ticked but %q is %s; run the full loop", f, reason))
		}
	}
	return problems
}
