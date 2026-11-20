package main

import (
	"strings"
	"testing"
)

func TestDocsOnlyReason(t *testing.T) {
	tests := []struct {
		path string
		want string // "" means the path fits the shortcut
	}{
		{"README.md", ""},
		{"SECURITY.md", ""},
		{"internal/redact/NOTES.md", ""},
		{"docs/architecture.md", ""},
		{"docs/adr/0018-new.md", ""},
		{"docs/schemas/report-v1.json", ""},
		{"docs/adr/dependencies.txt", "a setting make budget reads"},
		{"DOCS/ADR/Dependencies.TXT", "a setting make budget reads"},
		{"CHANGES.MD", ""},
		{"AGENTS.md", "a policy file"},
		{"CLAUDE.md", "a policy file"},
		{"CONTRIBUTING.md", "a policy file"},
		{".github/PULL_REQUEST_TEMPLATE.md", "a policy file"},
		{"internal/gateway/CLAUDE.md", "a policy file"},
		{"docs/agents.md", "a policy file"},
		{"docs/pull_request_template.md", "a policy file"},
		{".github/PULL_REQUEST_TEMPLATE/security.md", "a policy file"},
		{".github/workflows/ci.yml", "workflows or settings"},
		{".github/settings/release-environment.json", "workflows or settings"},
		{".github/notes.md", "workflows or settings"},
		{".claude/agents/tester.md", "workflows or settings"},
		{"docs/tool.go", "code or a build file"},
		{"docs/go.mod", "code or a build file"},
		{"docs/Makefile", "code or a build file"},
		{"docs/rules.mk", "code or a build file"},
		{"docs/ci/action.yml", "code or a build file"},
		{"Makefile", "code or a build file"},
		{"internal/redact/redact.go", "code or a build file"},
		{"go.mod", "code or a build file"},
		{".gitignore", "neither *.md nor under docs/"},
		{"Docs/x.txt", "neither *.md nor under docs/"},
		{"prompts/reader.txt", "neither *.md nor under docs/"},
		{"internal/report/testdata/golden/complete.md", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := docsOnlyReason(tt.path); got != tt.want {
				t.Fatalf("docsOnlyReason(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestDocsOnlyProblems(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  string // "" means no problem
	}{
		{"docs only", []string{"README.md", "docs/map.md"}, ""},
		{"one code file", []string{"README.md", "internal/x.go"}, `"internal/x.go" is code or a build file`},
		{"an excluded file", []string{"docs/map.md", "AGENTS.md"}, `"AGENTS.md" is a policy file`},
		{"no files", nil, "no changed file was listed"},
		{"odd name is quoted", []string{"a\nb.go"}, `"a\nb.go"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(docsOnlyProblems(tt.files), "\n")
			if tt.want == "" && got != "" {
				t.Fatalf("unexpected problems: %s", got)
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("problems %q do not contain %q", got, tt.want)
			}
		})
	}
}
