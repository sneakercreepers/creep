package presets

import (
	"strings"
	"testing"
)

// TestEmbeddedPresets is the CI schema check: every shipped preset parses,
// lists its tools-off flags in args, and builds a command line.
func TestEmbeddedPresets(t *testing.T) {
	files, err := embeddedFiles()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseAll(files); err != nil {
		t.Fatal(err)
	}
	want := []string{"claude-code", "codex", "gemini", "ollama"}
	if got := Names(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for _, name := range want {
		p, err := Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.CommandLine("llama3.1:8b"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		// Only presets whose CLI keeps no tool that reads the host may say none.
		if wantNone := name == "claude-code" || name == "ollama"; wantNone != (p.HostReads == HostReadsNone) {
			t.Errorf("%s: host_reads = %q", name, p.HostReads)
		}
		// Only claude-code was checked by hand against the real CLI (#7).
		if p.IsVerified() != (name == "claude-code") {
			t.Errorf("%s: verified = %v", name, p.IsVerified())
		}
	}
}

// The command lines the docs and the canary's fix messages promise.
func TestCommandLines(t *testing.T) {
	tests := []struct{ preset, model, want string }{
		{"claude-code", "", `claude -p --tools "" --strict-mcp-config --output-format text`},
		{"gemini", "", "gemini --skip-trust --approval-mode default --extensions none --allowed-mcp-server-names creep-no-mcp-server --output-format text"},
		{"codex", "", "codex exec --sandbox read-only --ignore-user-config -c features.shell_tool=false -c features.view_image=false -c features.apps=false -c features.plugins=false -c features.image_generation=false -c web_search=disabled -c \"project_root_markers=[]\" --skip-git-repo-check --ephemeral --color never -"},
		{"ollama", "qwen3:8b", "ollama run qwen3:8b --format json"},
		{"ollama", "library/llama3.1:8b-q4_K_M", "ollama run library/llama3.1:8b-q4_K_M --format json"},
	}
	for _, tt := range tests {
		p, err := Lookup(tt.preset)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.CommandLine(tt.model)
		if err != nil || got != tt.want {
			t.Errorf("%s: got %q, %v; want %q", tt.preset, got, err, tt.want)
		}
	}
}

// Protection: model.name is the only configured value that reaches argv;
// it can never become a flag, a second argument or a quote break-out.
func TestModelNameCannotInjectArguments(t *testing.T) {
	p, err := Lookup("ollama")
	if err != nil {
		t.Fatal(err)
	}
	for _, model := range []string{"", "--insecure", "-x", "a b", `a"b`, "a'b", "a;b", "a\nb", "a\x00b", "llama3\n", "llama3\r\n", " llama3", "a$(id)", strings.Repeat("a", 129)} {
		if got, err := p.CommandLine(model); err == nil {
			t.Errorf("model %q accepted: %q", model, got)
		}
	}
}

func TestLookupUnknown(t *testing.T) {
	for _, name := range []string{"nope", "../claude-code", "claude-code.yaml", "Claude-Code", ""} {
		if _, err := Lookup(name); err == nil || !strings.Contains(err.Error(), "unknown preset") {
			t.Errorf("Lookup(%q) = %v", name, err)
		}
	}
}

func TestQuoteArg(t *testing.T) {
	tests := map[string]string{
		"-p": "-p", "": `""`, "a b": `"a b"`, "a|b": `"a|b"`, `say "hi"`: `'say "hi"'`, "it's": `"it's"`,
	}
	for in, want := range tests {
		if got := quoteArg(in); got != want {
			t.Errorf("quoteArg(%q) = %q, want %q", in, got, want)
		}
	}
}

const valid = `version: 1
name: demo
description: A demo CLI.
docs: https://example.com/demo
program: demo
host_reads: none
verified: false
args: [-p, --no-tools]
tools_off:
  - [--no-tools]
`

// TestSchemaRejects covers the closed schema: every malformed preset fails
// with an error naming the problem.
func TestSchemaRejects(t *testing.T) {
	tests := []struct{ name, file, yaml, want string }{
		{"valid", "demo.yaml", valid, ""},
		{"shell string args", "demo.yaml", strings.Replace(valid, "args: [-p, --no-tools]", `args: "-p --no-tools"`, 1), "cannot unmarshal"},
		{"command line as program", "demo.yaml", strings.Replace(valid, "program: demo", `program: "demo -p"`, 1), "bare program name"},
		{"program path", "demo.yaml", strings.Replace(valid, "program: demo", "program: ./demo", 1), "bare program name"},
		{"absolute program", "demo.yaml", strings.Replace(valid, "program: demo", "program: /usr/bin/demo", 1), "bare program name"},
		{"unknown key", "demo.yaml", valid + "env: [AWS_SECRET_ACCESS_KEY]\n", "not found"},
		{"endpoint key", "demo.yaml", valid + "endpoint: https://evil.example\n", "not found"},
		{"duplicate key", "demo.yaml", valid + "program: other\n", "already defined"},
		{"second document", "demo.yaml", valid + "---\nversion: 1\n", "one YAML document"},
		{"missing tools_off", "demo.yaml", strings.Replace(valid, "tools_off:\n  - [--no-tools]\n", "", 1), "tools_off"},
		{"tools_off not in args", "demo.yaml", strings.Replace(valid, "args: [-p, --no-tools]", "args: [-p]", 1), "not in args"},
		{"tools_off split", "demo.yaml", strings.Replace(strings.Replace(valid, "[--no-tools]\n", "[--tools, \"\"]\n", 1), "args: [-p, --no-tools]", `args: [--tools, -p, ""]`, 1), "not in args"},
		{"empty tools_off entry", "demo.yaml", strings.Replace(valid, "  - [--no-tools]\n", "  - []\n", 1), "empty entry"},
		{"no_tools with flags", "demo.yaml", valid + "no_tools: true\n", "tools_off"},
		{"wrong version", "demo.yaml", strings.Replace(valid, "version: 1", "version: 2", 1), "version"},
		{"path traversal name", "demo.yaml", strings.Replace(valid, "name: demo", "name: ../demo", 1), "name"},
		{"slash name", "demo.yaml", strings.Replace(valid, "name: demo", "name: a/demo", 1), "name"},
		{"upper-case name", "demo.yaml", strings.Replace(valid, "name: demo", "name: Demo", 1), "name"},
		{"name differs from file", "other.yaml", valid, "file name"},
		{"control char arg", "demo.yaml", strings.Replace(valid, "[-p, --no-tools]", `["-p\u001b[2J", --no-tools]`, 1), "control"},
		{"newline arg", "demo.yaml", strings.Replace(valid, "[-p, --no-tools]", `["-p\n--yolo", --no-tools]`, 1), "control"},
		{"both quotes", "demo.yaml", strings.Replace(valid, "[-p, --no-tools]", `["a'\"b", --no-tools]`, 1), "both quote"},
		{"partial placeholder", "demo.yaml", strings.Replace(valid, "[-p, --no-tools]", `["-m={model}", --no-tools]`, 1), "whole argument"},
		{"two placeholders", "demo.yaml", strings.Replace(valid, "[-p, --no-tools]", `["{model}", "{model}", --no-tools]`, 1), "appears 2 times"},
		{"http docs", "demo.yaml", strings.Replace(valid, "https://example.com/demo", "http://example.com/demo", 1), "https"},
		{"empty description", "demo.yaml", strings.Replace(valid, "A demo CLI.", `""`, 1), "description"},
		{"missing verified", "demo.yaml", strings.Replace(valid, "verified: false\n", "", 1), "verified"},
		{"verified not a bool", "demo.yaml", strings.Replace(valid, "verified: false", "verified: maybe", 1), "cannot unmarshal"},
		{"missing host_reads", "demo.yaml", strings.Replace(valid, "host_reads: none\n", "", 1), "host_reads"},
		{"bad host_reads", "demo.yaml", strings.Replace(valid, "host_reads: none", "host_reads: some", 1), "host_reads"},
		{"unbounded without detail", "demo.yaml", strings.Replace(valid, "host_reads: none", "host_reads: unbounded", 1), "host_reads_detail"},
		{"detail without unbounded", "demo.yaml", valid + "host_reads_detail: reads files\n", "host_reads_detail"},
		{"detail with control char", "demo.yaml", strings.Replace(valid, "host_reads: none", "host_reads: unbounded\nhost_reads_detail: \"x\\u001b[2J\"", 1), "host_reads_detail"},
		{"unbounded with detail", "demo.yaml", strings.Replace(valid, "host_reads: none", "host_reads: unbounded\nhost_reads_detail: it can read HOME", 1), ""},
		{"oversized", "demo.yaml", valid + "# " + strings.Repeat("x", maxFileBytes), "bytes"},
	}
	for _, tt := range tests {
		_, err := parse(tt.file, []byte(tt.yaml))
		switch {
		case tt.want == "" && err != nil:
			t.Errorf("%s: %v", tt.name, err)
		case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
			t.Errorf("%s: err = %v, want it to mention %q", tt.name, err, tt.want)
		}
	}
}

func TestDuplicatePreset(t *testing.T) {
	files := []file{{"demo.yaml", []byte(valid)}, {"demo.yaml", []byte(valid)}}
	if _, err := parseAll(files); err == nil || !strings.Contains(err.Error(), "defined twice") {
		t.Errorf("err = %v", err)
	}
	if _, err := parseAll([]file{{"x/demo.yaml", []byte(valid)}, {"demo.yaml", []byte(valid)}}); err == nil {
		t.Error("duplicate across directories accepted")
	}
}
