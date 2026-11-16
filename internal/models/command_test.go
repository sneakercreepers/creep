package models

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// fakeCLIEnv switches this test binary into a fake model CLI (re-exec
// helper pattern): no real model, shell or network.
const (
	fakeCLIEnv   = "CREEP_FAKE_CLI"
	fakeStdinEnv = "CREEP_FAKE_STDIN" // where "answer" saves its stdin, outside its cwd
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeCLIEnv); mode != "" {
		os.Exit(fakeCLI(mode))
	}
	os.Exit(m.Run())
}

var trapNames = regexp.MustCompile(`named (creep-canary-[a-z0-9]+)|> (creep-canary-[a-z0-9]+)`)

func fakeCLI(mode string) int {
	in, _ := io.ReadAll(os.Stdin)
	switch mode {
	case "answer":
		if p := os.Getenv(fakeStdinEnv); p != "" {
			_ = os.WriteFile(p, in, 0o600) //nolint:gosec // G703: the test sets this path in t.TempDir()
		}
		fmt.Print(`{"vulnerable":true,"class":"sqli"}`)
	case "prose":
		fmt.Print(`Sure! {"vulnerable":true,"class":"sqli"}`)
	case "fenced":
		fmt.Print("```json\n{\"vulnerable\":true,\"class\":\"sqli\"}\n```")
	case "malformed":
		fmt.Print(`{"vulnerable":tru`)
	case "obey", "write":
		for i, m := range trapNames.FindAllStringSubmatch(string(in), -1) {
			if mode == "write" && i > 0 {
				break
			}
			_ = os.WriteFile(m[1]+m[2], []byte("ready"), 0o600)
		}
		fmt.Print(`{"done":true}`)
	case "fail":
		return 2
	}
	return 0
}

// commandModel builds a command model on the real gateway, consented by
// policy, running this binary in mode with the given claude-like flags.
func commandModel(t *testing.T, mode, flags string, retries int) (*HTTP, *gateway.Command, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stdin := t.TempDir() + string(os.PathSeparator) + "stdin"
	env := map[string]string{fakeCLIEnv: mode, fakeStdinEnv: stdin, "SystemRoot": os.Getenv("SystemRoot")}
	cmd, err := gateway.NewCommand(gateway.CommandOptions{
		Run: "'" + self + "' " + flags, Env: []string{fakeCLIEnv, fakeStdinEnv},
		Getenv: func(k string) string { return env[k] }, Timeout: 20 * time.Second, MaxOutputBytes: 1 << 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	consent, err := gateway.NewConsent(gateway.ConsentOptions{CI: true, Policy: []string{cmd.Endpoint()}})
	if err != nil {
		t.Fatal(err)
	}
	budget, err := gateway.NewBudget(gateway.BudgetOptions{MaxTokens: 1_000_000, MaxCalls: 10})
	if err != nil {
		t.Fatal(err)
	}
	log, err := gateway.OpenEgressLog(dir, consent, budget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	h, err := NewHTTP(Options{
		Contract: "command", Endpoint: cmd.Endpoint(), Model: "fake-cli", Structured: StructuredPrompt,
		MaxOutputTokens: 1024, Retries: retries, Send: ThroughCommand(log, cmd),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, cmd, dir
}

// Acceptance (#6): the redacted prompt reaches the CLI's stdin byte for
// byte as egress.log hashed and stored it, with its redaction counts; the
// reply gets the HTTP contract's strict decoding.
func TestCommandContractThroughEgressLog(t *testing.T) {
	h, _, dir := commandModel(t, "answer", "", 0)
	v, err := Complete[verdict](context.Background(), h, testRequest())
	if err != nil || !v.Vulnerable || v.Class != "sqli" {
		t.Fatalf("Complete = %+v, %v", v, err)
	}
	files := runFiles(t, dir)
	var req map[string]any
	if err := json.Unmarshal(bytes.SplitN(files["egress.log"], []byte("\n"), 2)[0], &req); err != nil {
		t.Fatal(err)
	}
	if req["purpose"] != "reader" || req["redactions"].(map[string]any)["password"] != 1.0 {
		t.Errorf("request line = %v", req)
	}
	stdin := files[req["payload_file"].(string)]
	sum := sha256.Sum256(stdin)
	if hex.EncodeToString(sum[:]) != req["sha256"] || !bytes.Contains(stdin, []byte("[REDACTED:password:1]")) {
		t.Errorf("payload %q does not match the request line", stdin)
	}
	if !bytes.Contains(stdin, []byte(`"additionalProperties":false`)) {
		t.Errorf("schema missing from the prompt: %q", stdin)
	}
}

// Malformed output is retried with the reason, then fails closed; a CLI
// failure is not retried.
func TestCommandContractRejects(t *testing.T) {
	tests := []struct {
		mode string
		want error
	}{
		{"prose", ErrInvalidOutput},
		{"fenced", ErrInvalidOutput},
		{"malformed", ErrInvalidOutput},
		{"fail", gateway.ErrCommandFailed},
		{"write", gateway.ErrToolUse},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			h, _, dir := commandModel(t, tt.mode, "", 1)
			req := testRequest()
			req.Prompt += " named creep-canary-abc"
			_, err := Complete[verdict](context.Background(), h, req)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			calls := strings.Count(string(runFiles(t, dir)["egress.log"]), `"type":"request"`)
			if want := map[bool]int{true: 2, false: 1}[tt.want == ErrInvalidOutput]; calls != want {
				t.Errorf("%d calls, want %d", calls, want)
			}
		})
	}
}

func TestNewHTTPCommandOptions(t *testing.T) {
	k, err := KeyFromEnv(env(fakeKey))
	if err != nil {
		t.Fatal(err)
	}
	bad := []Options{
		{Contract: "command", Endpoint: "https://x.example", Structured: StructuredPrompt},
		{Contract: "command", Endpoint: "command://x-0123456789abcdef", Structured: StructuredSchema},
		{Contract: "command", Endpoint: "command://x-0123456789abcdef", Structured: StructuredPrompt, Key: k},
	}
	for _, o := range bad {
		o.Model, o.MaxOutputTokens, o.Send = "m", 1, func(context.Context, gateway.Call) (*gateway.Reply, error) { return nil, nil }
		if _, err := NewHTTP(o); !errors.Is(err, ErrOptions) {
			t.Errorf("NewHTTP(%+v) = %v, want ErrOptions", o, err)
		}
	}
}
