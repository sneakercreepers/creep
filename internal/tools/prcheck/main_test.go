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
	data, err := json.Marshal(map[string]any{"pull_request": map[string]any{"number": 7, "body": body}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// baseAgentsText is an AGENTS.md with a loop section and a current state.
const baseAgentsText = "# AGENTS.md\n\n" + loopHeading + "\n\n- developer → tester\n\n## Current state\n\n- v0.1\n"

// newInputs writes the event, the file list, the base AGENTS.md and a tree
// whose AGENTS.md and docs/adr/ match the base.
func newInputs(t *testing.T, event, files string) inputs {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, rootAgents, baseAgentsText)
	if err := os.MkdirAll(filepath.Join(root, "docs", "adr"), 0o750); err != nil {
		t.Fatal(err)
	}
	return inputs{
		event:      writeTemp(t, "event.json", event),
		files:      writeTemp(t, "files", files),
		baseAgents: writeTemp(t, "base-agents.md", baseAgentsText),
		root:       root,
	}
}

func writeTree(t *testing.T, root, name, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	tests := []struct {
		name  string
		event string
		files string
		code  int
		want  string
	}{
		{"null body", eventJSON(t, nil), "Makefile\x00", 0, "prcheck: ok"},
		{"no claim, code changed", eventJSON(t, "- [x] AI-assisted: ran the agent loop"), "Makefile\x00", 0, "prcheck: ok"},
		{"docs-only fits", eventJSON(t, docsLine), "README.md\x00docs/map.md\x00", 0, "prcheck: ok"},
		{"docs-only with code", eventJSON(t, docsLine), "README.md\x00Makefile\x00", 1, `"Makefile" is code or a build file`},
		{"docs-only with a policy file", eventJSON(t, docsLine), "CONTRIBUTING.md\x00", 1, `"CONTRIBUTING.md" is a policy file`},
		{"docs-only with the allowlist", eventJSON(t, docsLine), "docs/adr/dependencies.txt\x00", 1, "a setting make budget reads"},
		{"docs-only with no files", eventJSON(t, docsLine), "", 1, "no changed file was listed"},
		{"not JSON", "{", "", 2, "decode event"},
		{"not a pull request event", `{"repository":{"full_name":"a/b"}}`, "", 2, "no pull request"},
		{"no number", `{"pull_request":{"body":"x"}}`, "", 2, "no pull request"},
		{"body of the wrong type", `{"pull_request":{"number":7,"body":5}}`, "", 2, "decode event"},
		{"policy change without an ADR", eventJSON(t, "no boxes"), "CLAUDE.md\x00", 1, `"CLAUDE.md" changes the agent-loop policy`},
		{"docs-only and policy without an ADR", eventJSON(t, docsLine), "CLAUDE.md\x00", 1, `"CLAUDE.md" is a policy file`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			code := run(newInputs(t, tt.event, tt.files), &out)
			if code != tt.code || !strings.Contains(out.String(), tt.want) {
				t.Fatalf("run() = %d, %q; want %d and %q", code, out.String(), tt.code, tt.want)
			}
		})
	}
}

// An input that cannot be read fails the check with exit 2, never passes.
func TestRunFailsClosedOnInputs(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	huge := writeTemp(t, "huge", strings.Repeat("a", maxInputBytes+1))
	tests := []struct {
		name string
		edit func(in *inputs)
	}{
		{"no event flag", func(in *inputs) { in.event = "" }},
		{"no files flag", func(in *inputs) { in.files = "" }},
		{"no base-agents flag", func(in *inputs) { in.baseAgents = "" }},
		{"missing event", func(in *inputs) { in.event = missing }},
		{"missing files", func(in *inputs) { in.files = missing }},
		{"missing base AGENTS.md", func(in *inputs) { in.baseAgents = missing }},
		{"event over the cap", func(in *inputs) { in.event = huge }},
		{"files over the cap", func(in *inputs) { in.files = huge }},
		{"base AGENTS.md over the cap", func(in *inputs) { in.baseAgents = huge }},
		{"event is a directory", func(in *inputs) { in.event = t.TempDir() }},
		{"head AGENTS.md is a directory", func(in *inputs) {
			in.files = writeTemp(t, "files", rootAgents)
			in.root = t.TempDir()
			if err := os.Mkdir(filepath.Join(in.root, rootAgents), 0o750); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := newInputs(t, eventJSON(t, "no boxes"), "")
			tt.edit(&in)
			var out bytes.Buffer
			if code := run(in, &out); code != 2 {
				t.Fatalf("run() = %d (%q), want 2", code, out.String())
			}
			if strings.Contains(out.String(), "prcheck: ok") {
				t.Fatalf("output %q claims the check passed", out.String())
			}
		})
	}
}
