package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/state"
	"github.com/sneakercreepers/creep/internal/verify"
)

// pocFixtureSecret signs the committed PoC fixtures. It is a fixed,
// public test value, as the reader's: a real run opens its store with the
// user's own secret, so these recordings are never served outside tests.
var pocFixtureSecret = bytes.Repeat([]byte{0x5a}, state.SecretBytes)

const (
	pocReplayDir   = "testdata/replay/poc"
	pocReplayModel = "replay-model"
	pocReplayApp   = "../../testdata/apps/flask/vulnerable"
)

// pocCase is one finding of the vulnerable Flask app with a template that
// proves its class, and the PoC the synthesized model answers with.
type pocCase struct {
	name     string
	class    string // report class
	target   reader.Target
	template string
	poc      map[string]any
}

var pocCases = []pocCase{
	{"sqli", "sqli", reader.Target{Hypothesis: 1, Class: reader.ClassSQLInjection, Path: "app.py", SourceLine: 40, SinkLine: 44},
		verify.TemplateSQLPayload, map[string]any{
			"template": "sql_payload", "http_request": nil, "http_sequence": nil, "path_payload": nil,
			"sql_payload": map[string]any{
				"request": map[string]any{"method": "GET", "path": "/notes/search?q=__CREEP_PAYLOAD__", "headers": []any{}, "content_type": "", "body": ""},
				"context": "string", "technique": "delay",
			},
		}},
	{"path_traversal", "path_traversal", reader.Target{Hypothesis: 2, Class: reader.ClassPathTraversal, Path: "app.py", SourceLine: 66, SinkLine: 68},
		verify.TemplatePathPayload, map[string]any{
			"template": "path_payload", "http_request": nil, "http_sequence": nil, "sql_payload": nil,
			"path_payload": map[string]any{
				"request": map[string]any{"method": "GET", "path": "/attachments/__CREEP_PAYLOAD__", "headers": []any{}, "content_type": "", "body": ""},
				"style":   "encoded", "depth": 6,
			},
		}},
}

// Acceptance (#25, AGENTS.md): the PoC request replays at every tier from
// its committed fixture, through the reader's real slice of a testdata app
// and askPoC, with no network, no key and no model call, to a PoC that
// Build accepts and whose template proves the class.
// Regenerate with: go test ./internal/cli -run TestPoCReplay -update
func TestPoCReplay(t *testing.T) {
	for _, tier := range []verify.Tier{verify.TierS, verify.TierM, verify.TierL} {
		t.Run(string(tier), func(t *testing.T) {
			store, mode := pocFixtureStore(t, tier)
			calls := 0
			for _, c := range pocCases {
				p, err := askPoC(context.Background(), pocReplayClient(t, store, mode, c, &calls), tier, c.class, pocSlice(t, tier, c.target))
				if err != nil {
					t.Fatalf("%s: %v", c.name, err)
				}
				if p.Template() != c.template || !verify.Fits(c.class, p) {
					t.Errorf("%s: template %s", c.name, p.Template())
				}
			}
			if !*updateGolden && calls != 0 {
				t.Fatalf("replay made %d model calls", calls)
			}
			if n := len(pocFixtureFiles(t, pocFixtureDir(tier))); n != len(pocCases) {
				t.Fatalf("%d fixture files for %d cases; rerun with -update", n, len(pocCases))
			}
		})
	}
}

// Protection: replay never falls back to the model. A request that is not
// the recorded one (another class, so another user turn) misses and stops
// the stage; it is not sent.
func TestPoCReplayMissStops(t *testing.T) {
	if *updateGolden {
		t.Skip("recording")
	}
	store, mode := pocFixtureStore(t, verify.TierM)
	c, calls := pocCases[0], 0
	_, err := askPoC(context.Background(), pocReplayClient(t, store, mode, c, &calls), verify.TierM, "template_injection", pocSlice(t, verify.TierM, c.target))
	if !errors.Is(err, errStopPoCs) || !errors.Is(err, state.ErrNotRecorded) || calls != 0 {
		t.Fatalf("unrecorded PoC request: %v after %d calls, want a stop with no call", err, calls)
	}
}

func pocSlice(t *testing.T, tier verify.Tier, target reader.Target) reader.Slice {
	t.Helper()
	red, err := redact.New()
	if err != nil {
		t.Fatal(err)
	}
	read := func(p string) ([]byte, error) { return os.ReadFile(filepath.Join(pocReplayApp, filepath.FromSlash(p))) }
	rep, err := reader.Slicer{Redactor: red, Tier: reader.Tier(tier), Read: read}.Build([]reader.Target{target})
	if err != nil || len(rep.Slices) != 1 {
		t.Fatalf("slice %+v: %v", target, err)
	}
	return rep.Slices[0]
}

// pocReplayClient answers through store, keyed by the exact request body;
// with -update the synthesized model answers c.poc.
func pocReplayClient(t *testing.T, store *state.Store, mode state.Mode, c pocCase, calls *int) *models.HTTP {
	t.Helper()
	send := func(_ context.Context, call gateway.Call) (*gateway.Reply, error) {
		body, err := store.Respond(mode, pocReplayKey(call), func() ([]byte, error) {
			*calls++
			if !*updateGolden {
				return nil, errors.New("replay must not call the model")
			}
			return chatReply(c.poc)
		})
		if err != nil {
			return nil, err
		}
		return &gateway.Reply{ID: "replay", Status: 200, Body: body}, nil
	}
	client, err := models.NewHTTP(models.Options{
		Contract: "openai", Endpoint: "https://models.replay.invalid/v1", Model: pocReplayModel,
		Structured: models.StructuredSchema, MaxOutputTokens: 1024, Send: send,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func pocReplayKey(c gateway.Call) state.Key {
	sum := sha256.Sum256(c.Payload)
	return state.Key{ContentHash: hex.EncodeToString(sum[:]), Model: c.Model, PromptVersion: fmt.Sprintf("poc.v%d", verify.PromptVersion)}
}

func pocFixtureDir(tier verify.Tier) string {
	return filepath.Join(pocReplayDir, strings.ToLower(string(tier)))
}

// pocFixtureStore records into the tier's fixture directory with -update,
// dropping old recordings first; otherwise it replays a copy, so the test
// never writes into the repository.
func pocFixtureStore(t *testing.T, tier verify.Tier) (*state.Store, state.Mode) {
	t.Helper()
	dir, mode := pocFixtureDir(tier), state.ModeReplay
	if *updateGolden {
		if err := os.RemoveAll(filepath.Join(dir, "cache")); err != nil {
			t.Fatal(err)
		}
		mode = state.ModeRecord
	} else {
		dir = copyPoCFixtures(t, dir)
	}
	store, err := state.OpenWithSecret(dir, pocFixtureSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, mode
}

func copyPoCFixtures(t *testing.T, dir string) string {
	t.Helper()
	to := t.TempDir()
	if err := os.Mkdir(filepath.Join(to, "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range pocFixtureFiles(t, dir) {
		data, err := os.ReadFile(filepath.Join(dir, "cache", name))
		if err != nil {
			t.Fatal(err)
		}
		// G703: name was listed from the fixture directory.
		if err := os.WriteFile(filepath.Join(to, "cache", name), data, 0o600); err != nil { //nolint:gosec
			t.Fatal(err)
		}
	}
	return to
}

func pocFixtureFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatalf("no PoC fixtures in %s (run go test ./internal/cli -run TestPoCReplay -update): %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	return names
}
