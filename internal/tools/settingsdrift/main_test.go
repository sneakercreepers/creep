package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rulesetFile = `{"name":"main","bypass_actors":[],"rules":[
 {"type":"deletion"},
 {"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":true,
  "required_status_checks":[{"context":"lint","integration_id":15368},{"context":"budget","integration_id":15368}]}}]}`

// Drift is every file key missing or different live, and every extra or
// missing array item; read-only live keys and item order are not drift.
func TestDrift(t *testing.T) {
	tests := []struct {
		name string
		live string
		want []string // substrings of the drift lines, one per line; none = no drift
	}{
		{"live adds read-only keys and reorders", `{"id":1,"name":"main","bypass_actors":[],"_links":{},"rules":[
 {"type":"required_status_checks","parameters":{"do_not_enforce_on_create":false,"strict_required_status_checks_policy":true,
  "required_status_checks":[{"context":"budget","integration_id":15368},{"context":"lint","integration_id":15368}]}},
 {"type":"deletion"}]}`, nil},
		{"weaker flag live", strings.Replace(rulesetFile, `"strict_required_status_checks_policy":true`, `"strict_required_status_checks_policy":false`, 1),
			[]string{".rules[1].parameters.strict_required_status_checks_policy: file true, live false"}},
		{"missing check live", strings.Replace(rulesetFile, `{"context":"lint","integration_id":15368},`, "", 1),
			[]string{".rules[1].parameters.required_status_checks: file has 2 items, live 1"}},
		{"extra bypass actor live", strings.Replace(rulesetFile, `"bypass_actors":[]`, `"bypass_actors":[{"actor_id":5}]`, 1),
			[]string{`.bypass_actors: file has 0 items, live 1; only in file [], only live [{"actor_id":5}]`}},
		{"extra rule live", strings.Replace(rulesetFile, `{"type":"deletion"},`, `{"type":"deletion"},{"type":"creation"},`, 1),
			[]string{`.rules: file has 2 items, live 3`}},
		{"key missing live", `{"name":"main","rules":[]}`,
			[]string{".bypass_actors: file [], live has no such key", ".rules: file has 2 items, live 0"}},
		{"type differs", `{"name":"main","bypass_actors":"none","rules":[{"type":"deletion"},{"type":"x"}]}`,
			[]string{`.bypass_actors: file [], live "none"`, `.rules[1].parameters: file {`, `.rules[1].type: file "required_status_checks", live "x"`}},
		{"number compared exactly", strings.Replace(rulesetFile, `"integration_id":15368}]`, `"integration_id":15368.0}]`, 1),
			[]string{".rules[1].parameters.required_status_checks[1].integration_id: file 15368, live 15368.0"}},
		{"live is not an object", `[]`, []string{".: file {"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			code, out := runFiles(t, dir, rulesetFile, tt.live)
			lines := driftLines(out)
			if len(lines) != len(tt.want) {
				t.Fatalf("got %d drift lines, want %d:\n%s", len(lines), len(tt.want), out)
			}
			for i, w := range tt.want {
				if !strings.Contains(lines[i], w) {
					t.Errorf("line %d = %q, want it to contain %q", i, lines[i], w)
				}
			}
			wantCode := 0
			if len(tt.want) > 0 {
				wantCode = 1
			}
			if code != wantCode {
				t.Errorf("exit %d, want %d", code, wantCode)
			}
		})
	}
}

// Inputs that cannot be read or decoded exit 2, so the check never passes
// on a failed fetch.
func TestUnreadableInputFailsClosed(t *testing.T) {
	dir := t.TempDir()
	good := write(t, dir, "good.json", `{"a":1}`)
	tests := []struct {
		name string
		args []string
	}{
		{"usage", []string{"x", good}},
		{"missing file", []string{"x", good, filepath.Join(dir, "absent.json")}},
		{"directory", []string{"x", good, dir}},
		{"empty", []string{"x", good, write(t, dir, "empty.json", "")}},
		{"not JSON", []string{"x", good, write(t, dir, "bad.json", "gh: Not Found (HTTP 404)")}},
		{"two values", []string{"x", good, write(t, dir, "two.json", `{"a":1} {"a":2}`)}},
		{"oversized", []string{"x", good, write(t, dir, "big.json", `"`+strings.Repeat("a", maxInputBytes)+`"`)}},
		{"bad file", []string{"x", write(t, dir, "badfile.json", "{"), good}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := run(tt.args, &out); code != 2 {
				t.Errorf("exit %d, want 2; output %q", code, out.String())
			}
		})
	}
}

// Live text is printed with every non-ASCII or control rune escaped, so a
// value from GitHub cannot fake a line or hide characters.
func TestLiveTextEscaped(t *testing.T) {
	dir := t.TempDir()
	code, out := runFiles(t, dir, `{"name":"main"}`, `{"name":"main\u202e\nok fake"}`)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if strings.Count(out, "\n") != 1 || strings.ContainsRune(out, '\u202e') || !strings.Contains(out, `\u202e\nok fake`) {
		t.Errorf("output not escaped: %q", out)
	}
}

// Every committed ruleset and setting decodes and matches itself, so a
// malformed file fails make check rather than the maintainer's run.
func TestCommittedSettingsDecode(t *testing.T) {
	var files []string
	for _, dir := range []string{"rulesets", "settings"} {
		m, err := filepath.Glob(filepath.Join("..", "..", "..", ".github", dir, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 9 {
		t.Fatalf("found %d settings files, want at least 9", len(files))
	}
	for _, f := range files {
		var out bytes.Buffer
		if code := run([]string{f, f, f}, &out); code != 0 {
			t.Errorf("%s: exit %d: %s", f, code, out.String())
		}
	}
}

func runFiles(t *testing.T, dir, file, live string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := run([]string{"ruleset main", write(t, dir, "file.json", file), write(t, dir, "live.json", live)}, &out)
	return code, out.String()
}

func driftLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(l, "drift ") {
			lines = append(lines, l)
		}
	}
	return lines
}

func write(t *testing.T, dir, name, data string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
