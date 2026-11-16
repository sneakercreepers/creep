package models

import (
	"context"
	"errors"
	"os"
	"testing"
)

// fakeToolUse is what a model CLI with tools leaves behind besides the
// trap's own file: only the shell command's output ("run"), a file the trap
// never named ("stray"), or a directory ("mkdir").
func fakeToolUse(mode, prompt string) {
	switch mode {
	case "run":
		if m := trapNames.FindAllStringSubmatch(prompt, -1); len(m) == 2 {
			_ = os.WriteFile(m[1][2], []byte("ready"), 0o600)
		}
	case "stray":
		_ = os.WriteFile("notes.txt", []byte("ready"), 0o600)
	case "mkdir":
		_ = os.Mkdir(".cache", 0o700)
	}
}

// canaryMissed reports a fake CLI the canary let through: the protection
// check of TestToolCanaryProtection.
func canaryMissed(t *testing.T, mode string) bool {
	t.Helper()
	h, cmd, _ := commandModel(t, mode, "-p", 0)
	err := NewCanary().Check(context.Background(), h, cmd)
	var te *ToolsEnabledError
	return !errors.As(err, &te)
}

// Protection (#17): the tool canary detects a model CLI with tools, whatever
// trace its tools leave in the working directory. The tool-free CLI is the
// deliberately broken fixture: a CLI the canary cannot see, which the check
// must report as missed, so it cannot pass vacuously.
func TestToolCanaryProtection(t *testing.T) {
	tests := []struct {
		mode       string
		wantMissed bool
	}{
		{"obey", false},  // creates the file and runs the command
		{"write", false}, // creates the file only
		{"run", false},   // runs the command only
		{"stray", false}, // writes a file the trap never named
		{"mkdir", false}, // creates a directory
		{"answer", true}, // no tools: nothing to catch
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			if got := canaryMissed(t, tt.mode); got != tt.wantMissed {
				t.Fatalf("canary missed = %v, want %v", got, tt.wantMissed)
			}
		})
	}
}
