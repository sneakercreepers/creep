package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func eventJSON(t *testing.T, body any) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"pull_request": map[string]any{"number": 7, "body": body},
		"repository":   map[string]any{"full_name": repo},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRun(t *testing.T) {
	links := tester + " " + auditor
	tests := []struct {
		name  string
		event string
		files string
		code  int
		want  string
	}{
		{"loop with links", eventJSON(t, loopLine+links), "internal/x.go\x00", 0, "prcheck: ok"},
		{"loop without links", eventJSON(t, loopLine+"<!-- links -->"), "internal/x.go\x00", 1, "agent-loop box links 0"},
		{"null body", eventJSON(t, nil), "", 0, "prcheck: ok"},
		{"docs-only fits", eventJSON(t, docsLine+auditor), "README.md\x00docs/map.md\x00", 0, "prcheck: ok"},
		{"docs-only with code", eventJSON(t, docsLine+auditor), "README.md\x00Makefile\x00", 1, `"Makefile" is code or a build file`},
		{"docs-only with a policy file", eventJSON(t, docsLine+auditor), "CONTRIBUTING.md\x00", 1, `"CONTRIBUTING.md" is a policy file`},
		{"docs-only with no files", eventJSON(t, docsLine+auditor), "", 1, "no changed file was listed"},
		{"files ignored without docs-only", eventJSON(t, "no boxes"), "Makefile\x00", 0, "prcheck: ok"},
		{"not JSON", "{", "", 2, "decode event"},
		{"not a pull request event", `{"repository":{"full_name":"a/b"}}`, "", 2, "no pull request"},
		{"no repository", `{"pull_request":{"number":7}}`, "", 2, "no pull request"},
		{"body of the wrong type", `{"pull_request":{"number":7,"body":5},"repository":{"full_name":"a/b"}}`, "", 2, "decode event"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			code := run(writeTemp(t, "event.json", tt.event), writeTemp(t, "files", tt.files), &out)
			if code != tt.code || !strings.Contains(out.String(), tt.want) {
				t.Fatalf("run() = %d, %q; want %d and %q", code, out.String(), tt.code, tt.want)
			}
		})
	}
}

// An input that cannot be read fails the check with exit 2, never passes.
func TestRunFailsClosedOnInputs(t *testing.T) {
	event := writeTemp(t, "event.json", eventJSON(t, "no boxes"))
	files := writeTemp(t, "files", "")
	missing := filepath.Join(t.TempDir(), "missing")
	huge := writeTemp(t, "huge", strings.Repeat("a", maxInputBytes+1))
	tests := []struct {
		name, event, files string
	}{
		{"no event flag", "", files},
		{"no files flag", event, ""},
		{"missing event", missing, files},
		{"missing files", event, missing},
		{"event over the cap", huge, files},
		{"files over the cap", event, huge},
		{"event is a directory", t.TempDir(), files},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := run(tt.event, tt.files, &out); code != 2 {
				t.Fatalf("run() = %d (%q), want 2", code, out.String())
			}
			if strings.Contains(out.String(), "prcheck: ok") {
				t.Fatalf("output %q claims the check passed", out.String())
			}
		})
	}
}
