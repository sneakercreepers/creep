package gateway

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func commandCall(c *Command, payload string) Call {
	return Call{
		Endpoint: c.Endpoint(), Model: "command", Purpose: "reader",
		Payload: []byte(payload), Redactions: map[string]int{"SECRET_AWS": 1}, ReserveTokens: 100,
	}
}

// Acceptance (#6): the payload reaches the program byte for byte through
// the same write-ahead egress.log and payload file as an HTTP call.
func TestExecLogsWriteAhead(t *testing.T) {
	dir := runDir(t)
	l := openLog(t, dir)
	c := fakeCommand(t, "echo", 10*time.Second)
	payload := "code <SECRET_AWS_1>"
	r, err := l.Exec(context.Background(), c, commandCall(c, payload))
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if string(r.Body) != payload || r.Status != 200 {
		t.Fatalf("reply = %d %q", r.Status, r.Body)
	}
	lines := readLines(t, dir)
	if len(lines) != 2 || lines[0]["type"] != "request" || lines[1]["outcome"] != OutcomeResponse {
		t.Fatalf("lines = %v", lines)
	}
	if lines[0]["endpoint"] != c.Endpoint() || lines[0]["redactions"].(map[string]any)["SECRET_AWS"] != 1.0 {
		t.Errorf("request line = %v", lines[0])
	}
	stored, err := os.ReadFile(filepath.Join(dir, lines[0]["payload_file"].(string)))
	if err != nil || string(stored) != payload {
		t.Errorf("payload file = %q, %v", stored, err)
	}
}

// Security (#6): the program gets only the base and declared variables, and
// runs in an empty temp directory, never the caller's (the repository).
func TestExecIsolatesProcess(t *testing.T) {
	l := openLog(t, runDir(t))
	c := fakeCommand(t, "env", 10*time.Second)
	r, err := l.Exec(context.Background(), c, commandCall(c, "x"))
	if err != nil {
		t.Fatal(err)
	}
	env := string(r.Body)
	if strings.Contains(env, "AWS_SECRET_ACCESS_KEY") || !strings.Contains(env, fakeCLIEnv+"=env") {
		t.Errorf("env = %q", env)
	}
	c = fakeCommand(t, "cwd", 10*time.Second)
	r, err = l.Exec(context.Background(), c, commandCall(c, "x"))
	if err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	got := strings.Split(string(r.Body), "\n")
	if len(got) != 2 || got[0] == wd || got[1] != "0" {
		t.Errorf("program cwd = %q (test cwd %q)", got, wd)
	}
}

func TestExecFailsClosed(t *testing.T) {
	tests := []struct {
		mode    string
		timeout time.Duration
		want    error
		outcome string
	}{
		{"touch", 10 * time.Second, ErrToolUse, OutcomeToolUse},
		{"huge", 10 * time.Second, ErrResponseTooLarge, OutcomeTooLarge},
		{"sleep", time.Second, ErrCommandTimeout, OutcomeTimeout},
		{"drip", time.Second, ErrCommandTimeout, OutcomeTimeout},
		{"exit3", 10 * time.Second, ErrCommandFailed, OutcomeCommandFailed},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			dir := runDir(t)
			l := openLog(t, dir)
			c := fakeCommand(t, tt.mode, tt.timeout)
			start := time.Now()
			r, err := l.Exec(context.Background(), c, commandCall(c, "x"))
			if r != nil || !errors.Is(err, tt.want) {
				t.Fatalf("Exec = %v, %v; want %v", r, err, tt.want)
			}
			if time.Since(start) > tt.timeout+waitDelay+5*time.Second {
				t.Errorf("took %s", time.Since(start))
			}
			lines := readLines(t, dir)
			if len(lines) != 2 || lines[1]["outcome"] != tt.outcome {
				t.Errorf("lines = %v", lines)
			}
			if strings.Contains(err.Error(), "secret prompt echo") {
				t.Errorf("error quotes stderr: %v", err)
			}
		})
	}
}

func TestExecToolUseNamesEntries(t *testing.T) {
	l := openLog(t, runDir(t))
	c := fakeCommand(t, "touch", 10*time.Second)
	_, err := l.Exec(context.Background(), c, commandCall(c, "x"))
	var tu *ToolUseError
	if !errors.As(err, &tu) || len(tu.Created) != 1 || tu.Created[0] != "creep-canary.txt" {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "creep-canary.txt") {
		t.Errorf("error quotes a name the model chose: %v", err)
	}
}

// A CLI's own temp files go to TMPDIR, outside the checked directory.
func TestExecTempFilesAreNotToolUse(t *testing.T) {
	l := openLog(t, runDir(t))
	c := fakeCommand(t, "tmpfile", 10*time.Second)
	if _, err := l.Exec(context.Background(), c, commandCall(c, "x")); err != nil {
		t.Fatal(err)
	}
}

// Consent and budget gate a command like an endpoint: a refusal runs
// nothing and writes nothing.
func TestExecRefusalsRunNothing(t *testing.T) {
	c := fakeCommand(t, "touch", 10*time.Second)
	tests := []struct {
		name    string
		consent *Consent
		budget  *Budget
		call    Call
		want    error
	}{
		{"no consent", newConsent(t, ConsentOptions{CI: true}), roomyBudget(t), commandCall(c, "x"), ErrNoConsent},
		{"over budget", allowAllConsent(t), newBudget(t, BudgetOptions{MaxTokens: 10, MaxCalls: 1}), commandCall(c, "x"), ErrBudgetExhausted},
		{"other endpoint", allowAllConsent(t), roomyBudget(t), Call{Endpoint: "command://x-0123456789abcdef", Model: "m", Purpose: "p", ReserveTokens: 1}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := runDir(t)
			l, err := OpenEgressLog(dir, tt.consent, tt.budget)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			_, err = l.Exec(context.Background(), c, tt.call)
			if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if data, _ := os.ReadFile(filepath.Join(dir, egressLogName)); len(bytes.TrimSpace(data)) != 0 {
				t.Errorf("egress.log = %q", data)
			}
		})
	}
}

// In CI a policy entry for the command endpoint is the only consent.
func TestExecPolicyConsent(t *testing.T) {
	c := fakeCommand(t, "echo", 10*time.Second)
	consent := newConsent(t, ConsentOptions{CI: true, Policy: []string{c.Endpoint()}})
	l, err := OpenEgressLog(runDir(t), consent, roomyBudget(t))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Exec(context.Background(), c, commandCall(c, "{}")); err != nil {
		t.Fatalf("Exec: %v", err)
	}
}
