package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

// hypothesisLine is the reader's HYPOTHESIS line, as it appears in the
// request body: the fake model answers from it, never from code.
var hypothesisLine = regexp.MustCompile(`HYPOTHESIS: ([a-z_]+), source line ([0-9]+), sink line ([0-9]+)`)

// fakeModel answers reader calls without a network: verdicts by reader
// class or by "class@sink line" (default not_vulnerable), an error for a
// class, and a call count.
type fakeModel struct {
	verdict    map[string]string // reader class or class@sink line -> verdict or "invalid"
	fail       map[string]error  // reader class, or "discover" -> send error
	missCanary bool              // discovery answers never report the canary
	claimAuth  bool              // discovery answers mark every repository line as an auth check
	calls      int
	discovered int // discovery calls
}

func (m *fakeModel) send(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
	m.calls++
	if answer, ok := discoveryAnswer(c.Payload, m.missCanary); ok {
		m.discovered++
		if err := m.fail["discover"]; err != nil {
			return nil, err
		}
		if m.claimAuth {
			answer["auth"] = authEverywhere(c.Payload)
		}
		body, err := chatReply(answer)
		return &gateway.Reply{ID: "fake", Status: 200, Body: body}, err
	}
	match := hypothesisLine.FindSubmatch(c.Payload)
	if match == nil {
		return nil, errors.New("fake model: no hypothesis in request")
	}
	if err := m.fail[string(match[1])]; err != nil {
		return nil, err
	}
	sink, _ := strconv.Atoi(string(match[3]))
	verdict := m.verdict[string(match[1])+"@"+string(match[3])]
	if verdict == "" {
		verdict = m.verdict[string(match[1])]
	}
	if verdict == "" {
		verdict = "not_vulnerable"
	}
	answer := map[string]any{"verdict": verdict, "evidence": []map[string]int{{"start": sink, "end": sink}}, "confidence": 80}
	if verdict == "invalid" {
		answer = map[string]any{"verdict": "maybe"}
	}
	body, err := chatReply(answer)
	return &gateway.Reply{ID: "fake", Status: 200, Body: body}, err
}

// chatReply wraps an answer as an OpenAI-compatible reply body.
func chatReply(answer any) ([]byte, error) {
	content, err := json.Marshal(answer)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": "chatcmpl-fake", "object": "chat.completion", "model": "test-model",
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": string(content)}, "finish_reason": "stop"}},
		"usage":   map[string]int{"prompt_tokens": 0, "completion_tokens": len(content)},
	})
}

// fixedCalibration stands in for calibrate.RunCached: a stored tier with
// one measured class, at a fixed date so output is deterministic.
func fixedCalibration(tier calibrate.Tier, err error) func(context.Context, calibrate.CacheOptions) (calibrate.Calibration, error) {
	return func(_ context.Context, opts calibrate.CacheOptions) (calibrate.Calibration, error) {
		if err != nil {
			return calibrate.Calibration{}, err
		}
		if opts.Model == nil || opts.Redactor == nil || opts.MaxAge <= 0 || opts.Seed != calibrationSeed {
			return calibrate.Calibration{}, errors.New("fake calibration: incomplete options")
		}
		return calibrate.Calibration{
			Result: calibrate.Result{
				Seed: calibrationSeed, TaskSet: "0123456789abcdef", PromptVersion: calibrate.PromptVersion, Tier: tier,
				Classes: []calibrate.ClassScore{{Class: calibrate.ClassSQLi, Score: calibrate.Score{Correct: 9, Total: 10}}},
			},
			Model: models.Identity{Model: "test-model"},
			At:    time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		}, nil
	}
}

// noModelDeps is what tests that are not about scanning pass: no test may
// reach a real model, whatever the developer's own config says.
var noModelDeps = scanDeps{
	connect: func(*config.Resolved, string, io.Writer) (modelLink, error) {
		return modelLink{}, errors.New("tests never connect to a model")
	},
	calibrate: fixedCalibration(calibrate.TierS, errors.New("tests never calibrate a model")),
}

func fakeDeps(m *fakeModel, tier calibrate.Tier) scanDeps {
	return scanDeps{
		connect: func(*config.Resolved, string, io.Writer) (modelLink, error) {
			return modelLink{send: m.send, close: func() error { return nil }}, nil
		},
		calibrate: fixedCalibration(tier, nil),
	}
}

// scanRepo makes a repository in a temporary directory, changes into it,
// and returns the path of a model config outside it. files maps names to
// contents; "@flask" or "@express" copies that vulnerable test app.
func scanRepo(t *testing.T, files map[string]string, extraConfig string) string {
	t.Helper()
	isolateUserConfig(t)
	repo := t.TempDir()
	for name, content := range files {
		if app, ok := strings.CutPrefix(content, "@"); ok {
			content = testApp(t, app)
		}
		path := filepath.Join(repo, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		// G703: name comes from the test's own table, inside t.TempDir().
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil { //nolint:gosec
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(t.TempDir(), "creep.yaml")
	data := "model:\n  contract: openai\n  endpoint: https://models.example.invalid/v1\n  name: test-model\n" + extraConfig
	if err := os.WriteFile(cfg, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	return cfg
}

// testApp reads the vulnerable variant of a testdata app ("flask",
// "express"); each holds one source file beside its Dockerfile.
func testApp(t *testing.T, app string) string {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "apps", app, "vulnerable")
	entries, err := os.ReadDir(dir)
	entries = slices.DeleteFunc(entries, func(e os.DirEntry) bool { return e.Name() == "Dockerfile" })
	if err != nil || len(entries) != 1 {
		t.Fatalf("testdata app %s: %v, %d source files", app, err, len(entries))
	}
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// runScanWith runs the CLI with deps and returns its result.
func runScanWith(deps scanDeps, args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = runWith(args, &out, &errOut, deps)
	return code, out.String(), errOut.String()
}
