package models

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Acceptance (#6): a CLI with tools enabled is caught, and the error names
// what it did and the missing flag.
func TestCanaryCatchesTools(t *testing.T) {
	tests := []struct {
		mode, flags   string
		write, ran    bool
		forbiddenText string
	}{
		{"obey", "-p --output-format json", true, true, "creep-canary-"},
		{"write", `-p --tools "" --output-format json`, true, false, "creep-canary-"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			h, cmd, _ := commandModel(t, tt.mode, tt.flags, 0)
			err := NewCanary().Check(context.Background(), h, cmd)
			var te *ToolsEnabledError
			if !errors.As(err, &te) || !errors.Is(err, ErrToolsEnabled) {
				t.Fatalf("Check = %v, want *ToolsEnabledError", err)
			}
			if te.WroteFile != tt.write || te.RanCommand != tt.ran {
				t.Errorf("wrote %v ran %v, want %v %v", te.WroteFile, te.RanCommand, tt.write, tt.ran)
			}
			// The fake is the test binary, not "claude", so the generic fix applies.
			if !strings.Contains(err.Error(), "turn off every tool") || strings.Contains(err.Error(), tt.forbiddenText) {
				t.Errorf("message = %q", err)
			}
		})
	}
}

// Acceptance (#6): the result is cached per command endpoint for the life
// of one Canary (one run), so the trap is sent once; a new Canary sends it
// again.
func TestCanaryCachedPerRun(t *testing.T) {
	h, cmd, dir := commandModel(t, "answer", "", 0)
	run := NewCanary()
	for range 3 {
		if err := run.Check(context.Background(), h, cmd); err != nil {
			t.Fatalf("Check: %v", err)
		}
	}
	if n := strings.Count(string(runFiles(t, dir)["egress.log"]), `"purpose":"canary"`); n != 1 {
		t.Fatalf("%d canary calls in one run, want 1", n)
	}
	if err := NewCanary().Check(context.Background(), h, cmd); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(runFiles(t, dir)["egress.log"]), `"purpose":"canary"`); n != 2 {
		t.Fatalf("%d canary calls after a second run, want 2", n)
	}
}

// A canary that cannot run fails closed.
func TestCanaryFailsClosed(t *testing.T) {
	h, cmd, _ := commandModel(t, "fail", "", 0)
	if err := NewCanary().Check(context.Background(), h, cmd); err == nil {
		t.Fatal("a failing CLI passed the canary")
	}
	other, _, _ := commandModel(t, "answer", "--other", 0)
	if err := NewCanary().Check(context.Background(), other, cmd); !errors.Is(err, ErrOptions) {
		t.Fatalf("mismatched model and command = %v, want ErrOptions", err)
	}
}

func TestCanaryFix(t *testing.T) {
	tests := []struct {
		program string
		args    []string
		want    string
	}{
		{"claude", []string{"-p", "--tools", "", "--strict-mcp-config"}, "it already has"},
		{"claude", []string{"-p", "--tools=", "--output-format", "json"}, "add --strict-mcp-config"},
		{"claude", []string{"-p", "--tools", "Bash", "--strict-mcp-config"}, `add --tools ""`},
		{"gemini", []string{"-p", "x", "--yolo"}, "remove --yolo"},
		{"gemini", []string{"--approval-mode=yolo", "-y"}, "remove --approval-mode and -y"},
		{"gemini", []string{"-p", "x"}, "no tool flag"},
		{"gemini", []string{"--approval-mode", "default", "--extensions", "none"}, "it already has --approval-mode default"},
		{"gemini", []string{"--approval-mode=default", "--yolo"}, "remove --approval-mode and --yolo"},
		{"codex", []string{"exec"}, "add --sandbox read-only and --ignore-user-config and -c features.shell_tool=false and -c features.view_image=false"},
		{"codex", []string{"exec", "-s", "read-only"}, "add --ignore-user-config and -c features.shell_tool=false"},
		{"codex", []string{"exec", "--sandbox=read-only", "--ignore-user-config", "-c", "features.shell_tool=false"}, "add -c features.view_image=false"},
		{"codex", []string{"exec", "--sandbox", "read-only", "--ignore-user-config", "-c", "features.shell_tool=true", "--config=features.view_image=false"}, "add -c features.shell_tool=false and -c features.apps=false"},
		{"codex", []string{"exec", "--sandbox", "read-only", "--ignore-user-config", "-c", "features.shell_tool=false", "-c", "features.view_image=false"}, "add -c features.apps=false and -c features.plugins=false and -c features.image_generation=false and -c web_search=disabled"},
		{"codex", []string{"exec", "--sandbox", "read-only", "--ignore-user-config", "-c", "features.shell_tool=false", "-c", "features.view_image=false", "-c", "features.apps=false", "--config", "features.plugins=false", "-c", "features.image_generation=false", "--config=web_search=disabled"}, "it already has --sandbox read-only"},
		{"codex", []string{"exec", "--sandbox", "read-only", "--ignore-user-config", "-c", "features.shell_tool=false", "-c", "features.view_image=false", "-c", "features.apps=false", "-c", "features.plugins=false", "-c", "features.image_generation=false", "-c", "web_search=live"}, "add -c web_search=disabled to"},
		{"llm", []string{"-m", "x", "-T", "shell"}, "remove -T"},
		{"ollama", []string{"run", "llama3"}, "ollama run has no tools"},
		{"mycli", nil, "turn off every tool"},
	}
	for _, tt := range tests {
		if got := canaryFix(tt.program, tt.args); !strings.HasPrefix(got, tt.want) {
			t.Errorf("canaryFix(%s %q) = %q, want prefix %q", tt.program, tt.args, got, tt.want)
		}
	}
}
