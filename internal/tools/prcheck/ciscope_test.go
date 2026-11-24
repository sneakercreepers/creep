package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCISkippable(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"SUPPORT.md", true},
		{"CODE_OF_CONDUCT.md", true},
		{"docs/design.md", true},
		{"docs/threat-model.md", true},
		{"docs/guides/new.md", true},
		// Read by make check, a test or CI lint.
		{"README.md", false},
		{"readme.MD", false},
		{"docs/architecture.md", false},
		{"docs/map.md", false},
		{"Docs/Map.md", false},
		{"docs/bench/results.md", false},
		{"docs/bench/results.json", false},
		{"docs/schemas/report-v1.json", false},
		{"docs/examples/creep-action.yml", false},
		// A *.md inside a package can be test data or embedded.
		{"internal/report/testdata/golden/complete.md", false},
		{"internal/redact/NOTES.md", false},
		{"Docs/x.md", false},
		// Outside the docs-only shortcut altogether.
		{"AGENTS.md", false},
		{"SECURITY.md", false},
		{"docs/adr/0018-docs-only-exclusions.md", false},
		{"docs/adr/dependencies.txt", false},
		{".github/workflows/ci.yml", false},
		{"docs/tool.go", false},
		{"Makefile", false},
		{".gitignore", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := ciSkippable(tt.path); got != tt.want {
				t.Fatalf("ciSkippable(%q) = %t, want %t", tt.path, got, tt.want)
			}
		})
	}
}

func TestDocsOnlyScope(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  bool
	}{
		{"only prose", []string{"SUPPORT.md", "docs/design.md"}, true},
		{"one checked doc", []string{"docs/design.md", "docs/map.md"}, false},
		{"one code file", []string{"docs/design.md", "internal/x.go"}, false},
		{"no files", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := docsOnlyScope(tt.files); got != tt.want {
				t.Fatalf("docsOnlyScope(%q) = %t, want %t", tt.files, got, tt.want)
			}
		})
	}
}

func TestRunCIScope(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := []struct {
		name     string
		files    string
		code     int
		wantOut  string
		wantErrs string
	}{
		{"docs only", write("docs", "SUPPORT.md\x00docs/design.md\x00"), 0, "docs_only=true\n", ""},
		{"code", write("code", "docs/design.md\x00main.go\x00"), 0, "docs_only=false\n", ""},
		{"empty list", write("empty", ""), 0, "docs_only=false\n", ""},
		{"missing list", filepath.Join(dir, "absent"), 2, "", "prcheck:"},
		{"no flag", "", 2, "", "-files is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := runCIScope(tt.files, &out, &errOut); code != tt.code {
				t.Fatalf("exit %d, want %d (%s)", code, tt.code, errOut.String())
			}
			if out.String() != tt.wantOut {
				t.Fatalf("stdout %q, want %q", out.String(), tt.wantOut)
			}
			if !strings.Contains(errOut.String(), tt.wantErrs) {
				t.Fatalf("stderr %q lacks %q", errOut.String(), tt.wantErrs)
			}
		})
	}
}
