package config

import (
	"strings"
	"testing"
)

// model: { preset: claude-code } resolves the command line through the
// command contract (#6), and explain names the preset as the source.
func TestPresetResolvesCommand(t *testing.T) {
	r, err := Load(Inputs{User: file("u", "model:\n  preset: claude-code\n")})
	if err != nil {
		t.Fatal(err)
	}
	m := r.Config.Model
	if m.Contract != "command" || m.Run != `claude -p --tools "" --strict-mcp-config --output-format text` {
		t.Errorf("model = %+v", m)
	}
	for _, e := range r.Explain() {
		if (e.Key == "model.run" || e.Key == "model.contract") && !strings.HasPrefix(e.Source, `preset "claude-code" via user`) {
			t.Errorf("%s source = %q", e.Key, e.Source)
		}
	}
}

// The flow-style form from the docs, and a model name from an operator
// layer for a preset that takes one.
func TestPresetWithModelName(t *testing.T) {
	r, err := Load(Inputs{
		User:    file("u", "model: { preset: ollama, name: \"qwen3:8b\" }\n"),
		Project: file("creep.yaml", "model:\n  tier: small\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Config.Model.Run != "ollama run qwen3:8b --format json" || r.Config.Model.Tier != "small" {
		t.Errorf("model = %+v", r.Config.Model)
	}
}

// Protection: the scanned repository cannot select or define the model
// command, through a preset or through the model name a preset passes on.
func TestProjectCannotChoosePreset(t *testing.T) {
	tests := []struct {
		name string
		in   Inputs
		want string
	}{
		{"project preset", Inputs{Project: file("creep.yaml", "model:\n  preset: claude-code\n")}, "cannot be set in the project file"},
		{"project preset over user", Inputs{User: file("u", "model:\n  preset: ollama\n  name: llama3\n"), Project: file("creep.yaml", "model:\n  preset: codex\n")}, "cannot be set in the project file"},
		{"project model for ollama", Inputs{User: file("u", "model:\n  preset: ollama\n"), Project: file("creep.yaml", "model:\n  name: evil.example/x/y\n")}, `key "model.name" cannot be set in the project file`},
		{"project contract over user preset", Inputs{User: file("u", "model:\n  preset: claude-code\n"), Project: file("creep.yaml", "model:\n  contract: openai\n")}, "cannot be set in the project file"},
		{"project contract command", Inputs{Project: file("creep.yaml", "model:\n  contract: command\n")}, "cannot be set in the project file"},
		{"project run", Inputs{Project: file("creep.yaml", "model:\n  run: claude -p\n")}, "cannot be set in the project file"},
	}
	for _, tt := range tests {
		if _, err := Load(tt.in); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v", tt.name, err)
		}
	}
}

func TestPresetRejects(t *testing.T) {
	tests := []struct {
		name string
		in   Inputs
		want string
	}{
		{"unknown", Inputs{User: file("u", "model:\n  preset: nope\n")}, "unknown preset"},
		{"path traversal", Inputs{User: file("u", "model:\n  preset: ../../etc/passwd\n")}, "unknown preset"},
		{"file name", Inputs{User: file("u", "model:\n  preset: claude-code.yaml\n")}, "unknown preset"},
		{"run and preset", Inputs{User: file("u", "model:\n  preset: claude-code\n  run: claude -p\n")}, "both choose"},
		{"flag run over preset", Inputs{User: file("u", "model:\n  preset: claude-code\n"), Flags: []Flag{{Name: "--model-run", Key: "model.run", Value: "llm"}}}, "both choose"},
		{"http contract", Inputs{User: file("u", "model:\n  preset: codex\n  contract: openai\n")}, "needs contract command"},
		{"ollama without model", Inputs{User: file("u", "model:\n  preset: ollama\n")}, "needs model.name"},
		{"ollama flag model", Inputs{User: file("u", "model:\n  preset: ollama\n  name: \"--insecure\"\n")}, "needs model.name"},
		{"policy run lock", Inputs{Policy: file("p", "locked: [model.run]\ndefaults:\n  model:\n    run: llm\n"), User: file("u", "model:\n  preset: codex\n")}, "locked by policy"},
		{"policy preset lock", Inputs{Policy: file("p", "locked: [model.preset]\ndefaults:\n  model:\n    preset: codex\n"), User: file("u", "model:\n  preset: gemini\n")}, "locked"},
	}
	for _, tt := range tests {
		if _, err := Load(tt.in); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
	}
}

// Protection (#7 A1): a policy lock binds even when it pins the default; a
// user or --config preset that would change a locked key is a config error.
func TestPresetRespectsPolicyLocks(t *testing.T) {
	user := file("u", "model:\n  preset: claude-code\n")
	tests := []struct {
		name, policy string
		in           Inputs
		want         string
	}{
		{"locked default run", "locked: [model.run]\n", Inputs{User: user}, "locked by policy"},
		{"locked run with value", "locked: [model.run]\ndefaults:\n  model:\n    run: llm\n", Inputs{User: user}, "locked by policy"},
		{"locked default contract", "locked: [model.contract]\n", Inputs{User: user}, `locked to "openai" by policy`},
		{"locked anthropic contract", "locked: [model.contract]\ndefaults:\n  model:\n    contract: anthropic\n", Inputs{User: user}, `locked to "anthropic"`},
		{"locked preset", "locked: [model.preset]\n", Inputs{User: user}, "locked by policy"},
		{"locked run via --config", "locked: [model.run]\n", Inputs{Explicit: file("c", "model:\n  preset: codex\n")}, "locked by policy"},
		{"locked contract via flag-free policy preset", "locked: [model.contract]\ndefaults:\n  model:\n    preset: codex\n", Inputs{}, "locked to \"openai\""},
	}
	for _, tt := range tests {
		tt.in.Policy = file("org.yaml", tt.policy)
		if _, err := Load(tt.in); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
	}
}

// A contract locked to command allows a preset, and explain keeps showing
// the policy as the source of the locked key.
func TestPresetUnderCommandContractLock(t *testing.T) {
	r, err := Load(Inputs{
		Policy: file("org.yaml", "locked: [model.contract]\ndefaults:\n  model:\n    contract: command\n"),
		User:   file("u", "model:\n  preset: claude-code\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range r.Explain() {
		if e.Key == "model.contract" && e.Source != `policy "org.yaml"` {
			t.Errorf("model.contract source = %q", e.Source)
		}
		if e.Key == "model.run" && !strings.HasPrefix(e.Source, `preset "claude-code"`) {
			t.Errorf("model.run source = %q", e.Source)
		}
	}
}

// A policy may pick the preset for every user; an explicit command contract
// next to a preset is fine.
func TestPolicyPreset(t *testing.T) {
	r, err := Load(Inputs{
		Policy: file("p", "locked: [model.preset]\ndefaults:\n  model:\n    preset: codex\n    contract: command\n"),
		User:   file("u", "model:\n  tier: large\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.Config.Model.Run, "codex exec --sandbox read-only") {
		t.Errorf("run = %q", r.Config.Model.Run)
	}
}
