package actionscripts

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// runLine is a composite step's run key; the Action keeps each on one line.
var runLine = regexp.MustCompile(`^\s+run:\s*(.*)$`)

// scriptRun is the only run the Action allows: one of its scripts by name.
var scriptRun = regexp.MustCompile(`^bash "\$GITHUB_ACTION_PATH/action/([a-z]+\.sh)"$`)

// Protection (ADR 0023): no input, event field or step output is ever
// expanded into shell text. Every run in action.yml is exactly
// `bash "$GITHUB_ACTION_PATH/action/<script>.sh"`, so expressions appear
// only under env and with, and every script in action/ is one of them.
// zizmor and actionlint check the same in CI; this test fails first and
// locally.
func TestActionRunsOnlyItsScripts(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var used []string
	for i, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		m := runLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		script := scriptRun.FindStringSubmatch(m[1])
		if script == nil {
			t.Errorf("action.yml:%d: run %q is not one of the Action's scripts by name", i+1, m[1])
			continue
		}
		used = append(used, script[1])
	}
	entries, err := os.ReadDir(filepath.Join(repoRoot, "action"))
	if err != nil {
		t.Fatal(err)
	}
	var scripts []string
	for _, e := range entries {
		scripts = append(scripts, e.Name())
	}
	slices.Sort(used)
	if !slices.Equal(used, scripts) {
		t.Errorf("action.yml runs %v, action/ holds %v: each script runs once and nothing else is there", used, scripts)
	}
}
