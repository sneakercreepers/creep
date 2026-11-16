package config

import (
	"fmt"
	"strings"
	"testing"
)

// Protection (pentest P2, #62): the scanned repository cannot pick the model
// or opt the operator into the sandbox; operator layers still can.
func TestProjectCannotChooseModelOrSandbox(t *testing.T) {
	tests := map[string]string{
		"model.name":      "model:\n  name: o1-pro\n",
		"sandbox.enabled": "sandbox:\n  enabled: true\n",
		"sandbox.runtime": "sandbox:\n  runtime: podman\n",
	}
	for key, yaml := range tests {
		t.Run(key, func(t *testing.T) {
			_, err := Load(Inputs{Project: file("creep.yaml", yaml)})
			want := fmt.Sprintf(`project "creep.yaml": key %q cannot be set in the project file`, key)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want containing %q", err, want)
			}
			if _, err := Load(Inputs{User: file("u", yaml)}); err != nil {
				t.Fatalf("user file: %v", err)
			}
		})
	}
}

// Protection (pentest P2, #62): the project file may lower the operator's
// spend and time limits, never raise them above what the layers before it
// set, whichever layer that was.
func TestProjectMayOnlyLowerLimits(t *testing.T) {
	keys := []struct {
		key, yaml   string // yaml has one %d
		builtin, lo int
	}{
		{"budget.max_tokens", "budget:\n  max_tokens: %d\n", 2_000_000, 1000},
		{"budget.max_calls", "budget:\n  max_calls: %d\n", 500, 1},
		{"model.timeout_seconds", "model:\n  timeout_seconds: %d\n", 300, 1},
		{"model.max_output_bytes", "model:\n  max_output_bytes: %d\n", 1 << 20, 1 << 10},
		{"calibration.cache_days", "calibration:\n  cache_days: %d\n", 30, 1},
	}
	for _, k := range keys {
		t.Run(k.key, func(t *testing.T) {
			project := func(v int) *File { return file("creep.yaml", fmt.Sprintf(k.yaml, v)) }
			raised := fmt.Sprintf("key %q cannot raise %d to %d in the project file", k.key, k.builtin, k.builtin+1)
			if _, err := Load(Inputs{Project: project(k.builtin + 1)}); err == nil || !strings.Contains(err.Error(), raised) {
				t.Fatalf("raise over default: err = %v, want containing %q", err, raised)
			}
			// The user's own lower value is the ceiling, not the default.
			user := file("u", fmt.Sprintf(k.yaml, k.lo+1))
			if _, err := Load(Inputs{User: user, Project: project(k.lo + 2)}); err == nil || !strings.Contains(err.Error(), `(set by user "u")`) {
				t.Fatalf("raise over user: err = %v", err)
			}
			for _, v := range []int{k.builtin, k.lo} {
				r, err := Load(Inputs{Project: project(v)})
				if err != nil || field(&r.Config, k.key).Int() != int64(v) || sourceOf(t, r, k.key) != `project "creep.yaml"` {
					t.Fatalf("lower to %d: err = %v", v, err)
				}
			}
			// Operator layers may raise.
			if _, err := Load(Inputs{User: file("u", fmt.Sprintf(k.yaml, k.builtin+1))}); err != nil {
				t.Fatalf("user raise: %v", err)
			}
		})
	}
}
