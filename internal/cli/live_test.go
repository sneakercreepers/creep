package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/sandbox"
)

// liveEnv turns on TestLiveAppVerifies: the live workflow sets it on a
// runner with Docker and the pinned images pulled. Elsewhere the test
// skips, since it builds and serves a real app.
const liveEnv = "CREEP_LIVE_VERIFY"

// liveApp is the test app that serves for real in the sandbox (#364).
var liveApp = filepath.Join("..", "..", "testdata", "apps", "flaskpg")

// liveModel answers like the synthesized model of the committed fixtures
// (fakeModel: discovery with its canary, the reader by class and sink
// line) and gives each class the PoC the committed PoC fixtures hold
// (pocCases), with no key and no network.
type liveModel struct{ fakeModel }

func (m *liveModel) send(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
	if !bytes.Contains(c.Payload, pocRequest) {
		return m.fakeModel.send(ctx, c)
	}
	m.pocCalls++
	for _, pc := range pocCases {
		// The payload is JSON, so the prompt's line break is `\n` there.
		if bytes.Contains(c.Payload, []byte(`class: `+pc.class+`\n`)) {
			body, err := chatReply(pc.poc)
			return &gateway.Reply{ID: "fake", Status: 200, Body: body}, err
		}
	}
	body, err := chatReply(map[string]any{"template": "none"})
	return &gateway.Reply{ID: "fake", Status: 200, Body: body}, err
}

// liveCase is one variant of the live app: the sink lines the model calls
// vulnerable and the findings that must come out verified.
type liveCase struct {
	variant  string
	claims   map[string]string
	verified []string
}

// The model claims both app.py sinks on both variants (expected.json's
// lines on the vulnerable one, the same handlers' calls on the safe twin),
// so on the safe twin only the oracle keeps them from being verified.
var liveCases = []liveCase{
	{"vulnerable", map[string]string{"sql_injection@33": "vulnerable", "path_traversal@39": "vulnerable"},
		[]string{"path_traversal app.py:39", "sqli app.py:33"}},
	{"safe", map[string]string{"sql_injection@31": "vulnerable", "path_traversal@37": "vulnerable"}, nil},
}

// TestLiveAppVerifies (#364): `creep scan --mode nightly` with the real
// sandbox builds the Flask app offline from its wheels, starts the empty
// database, runs the app's own migrate step, serves the app with the
// synthetic env, and runs each PoC 5 times. On the vulnerable app the SQL
// injection and the path traversal are verified 5 of 5; on the safe twin,
// with the same claims and PoCs, nothing is.
func TestLiveAppVerifies(t *testing.T) {
	if os.Getenv(liveEnv) == "" {
		t.Skipf("%s is not set: this test builds and serves a real app in the sandbox", liveEnv)
	}
	for _, tt := range liveCases {
		t.Run(tt.variant, func(t *testing.T) {
			findings, out := liveScan(t, tt)
			var verified []string
			for _, f := range findings {
				if f.Status != report.StatusVerified {
					continue
				}
				verified = append(verified, fmt.Sprintf("%s %s:%d", f.Class, f.Path, f.Line))
				if !strings.Contains(out, fmt.Sprintf("sandbox: PoC for %s (%s, ", f.ID, f.Class)) ||
					!strings.Contains(out, fmt.Sprintf("%s  %s:%d  verified in 5/5 runs", f.Class, f.Path, f.Line)) {
					t.Errorf("%s %s is not verified in 5/5 runs", f.ID, f.Class)
				}
			}
			slices.Sort(verified)
			if !slices.Equal(verified, tt.verified) {
				t.Errorf("verified %q, want %q", verified, tt.verified)
			}
			t.Logf("%s: verified %q\n%s", tt.variant, verified, out)
		})
	}
}

// liveScan copies a variant into a fresh repository, scans it nightly
// with the sandbox on and returns the report's findings and the output.
func liveScan(t *testing.T, tt liveCase) ([]report.Finding, string) {
	t.Helper()
	// Rootless Podman keeps its images under HOME, so HOME stays; creep's
	// own config, state key and cache move to a fresh directory.
	home := os.Getenv("HOME")
	isolateUserConfig(t)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	if home != "" {
		t.Setenv("HOME", home)
	}
	repo := t.TempDir()
	copyTree(t, filepath.Join(liveApp, tt.variant), repo)
	cfg := filepath.Join(t.TempDir(), "creep.yaml")
	data := "model:\n  contract: openai\n  endpoint: https://models.example.invalid/v1\n  name: test-model\n" + sandboxOn
	if err := os.WriteFile(cfg, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	m := &liveModel{fakeModel{verdict: tt.claims}}
	deps := fakeDeps(&m.fakeModel, calibrate.TierM)
	deps.connect = liveConnect(m)
	deps.sandbox = sandboxDeps{detect: sandbox.Detect, open: openSandbox}
	code, stdout, stderr := runScanWith(deps, "--config", cfg, "scan", "--mode", "nightly")
	out := stdout + stderr
	if code != 0 && code != 1 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	// Every claim must have had its PoC run, or nothing verified on the
	// safe twin would prove nothing.
	if ran := strings.Count(out, "sandbox: PoC for "); m.pocCalls != len(tt.claims) || ran != len(tt.claims) {
		t.Fatalf("%d PoC requests, %d PoCs ran, for %d claims\n%s", m.pocCalls, ran, len(tt.claims), out)
	}
	f, err := os.Open(filepath.Join(stateDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := report.ReadJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	return rep.Findings, out
}

func liveConnect(m *liveModel) func(*config.Resolved, string, io.Writer) (modelLink, error) {
	return func(*config.Resolved, string, io.Writer) (modelLink, error) {
		return modelLink{send: m.send, close: func() error { return nil }}, nil
	}
}

// copyTree copies the tree under src into the empty directory dst.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
}
