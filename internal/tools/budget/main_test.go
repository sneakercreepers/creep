package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// A step that cannot finish fails the budget with exit 2 wherever it sits in
// the list, so no guard can fail open by erroring (#140).
func TestRunFailsClosedOnStepError(t *testing.T) {
	failing := func(config) ([]string, error) { return nil, errors.New("step broke") }
	passing := func(config) ([]string, error) { return nil, nil }
	tests := []struct {
		name  string
		steps []func(config) ([]string, error)
	}{
		{"first step", []func(config) ([]string, error){failing, passing, passing}},
		{"middle step", []func(config) ([]string, error){passing, failing, passing}},
		{"last step", []func(config) ([]string, error){passing, passing, failing}},
		{"only step", []func(config) ([]string, error){failing}},
	}
	saved := steps
	t.Cleanup(func() { steps = saved })
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			steps = tt.steps
			var out bytes.Buffer
			if code := run(config{}, &out); code != 2 {
				t.Errorf("run() = %d, want 2", code)
			}
			if !strings.Contains(out.String(), "budget: step broke") {
				t.Errorf("output %q does not carry the step error", out.String())
			}
			if strings.Contains(out.String(), "budget: ok") {
				t.Errorf("output %q claims the budget passed", out.String())
			}
		})
	}
}
