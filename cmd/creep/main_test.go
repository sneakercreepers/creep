package main

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

// reexecEnv makes the test binary act as creep, so the real os.Exit path runs.
const reexecEnv = "CREEP_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(reexecEnv) == "1" {
		os.Args = append([]string{"creep"}, os.Args[1:]...)
		main()
		return
	}
	os.Exit(m.Run())
}

func TestProcessExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"version", []string{"version"}, 0},
		{"help", []string{"--help"}, 0},
		{"no args", nil, 2},
		{"unknown command", []string{"frobnicate"}, 2},
		{"unknown flag", []string{"--nope", "version"}, 2},
		{"invalid format", []string{"version", "--format", "xml"}, 2},
		{"missing config", []string{"--config", "does-not-exist.yaml", "version"}, 2},
		{"scan without a model fails closed", []string{"scan", "."}, 2},
		{"invalid format after positional", []string{"scan", ".", "--format", "xml"}, 2},
		{"short help", []string{"-h"}, 0},
		{"help command", []string{"help"}, 0},
		{"command help", []string{"version", "--help"}, 0},
		{"init writes creep.yaml in a fresh directory", []string{"init"}, 0},
		{"init extra args", []string{"init", "x"}, 2},
		{"unimplemented doctor fails closed", []string{"doctor"}, 2},
		{"unimplemented config fails closed", []string{"config"}, 2},
		{"version extra args", []string{"version", "x"}, 2},
		{"invalid log level", []string{"--log-level", "loud", "version"}, 2},
		{"config is a directory", []string{"--config", ".", "version"}, 2},
		{"flag after double dash is positional", []string{"version", "--", "--format=json"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A fresh directory and home: scan must never find the
			// developer's model config and reach a real model here.
			home := t.TempDir()
			cmd := exec.Command(os.Args[0], tt.args...)
			cmd.Dir = t.TempDir()
			cmd.Env = append(os.Environ(), reexecEnv+"=1", "HOME="+home, "XDG_CONFIG_HOME="+home,
				"AppData="+home, "LocalAppData="+home, "USERPROFILE="+home, "CREEP_POLICY=")
			if got := exitCode(t, cmd.Run()); got != tt.want {
				t.Errorf("exit code = %d, want %d", got, tt.want)
			}
		})
	}
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run creep: %v", err)
	}
	return exitErr.ExitCode()
}
