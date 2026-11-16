package reader

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/state"
)

// fixtureSecret signs the committed fixtures. It is a fixed, public test
// value: a real run opens its store with the user's own secret, so a
// recording signed with this one is never served outside tests.
var fixtureSecret = bytes.Repeat([]byte{0x5a}, state.SecretBytes)

const replayModelName = "replay-model"

// model answers one hypothesis with a provider reply body.
type model func(h appHypothesis) ([]byte, error)

// targets returns the variant's hypotheses as Targets, and each by its ID.
func (c appCase) targets(variant string) ([]Target, map[HypothesisID]appHypothesis) {
	var targets []Target
	byID := map[HypothesisID]appHypothesis{}
	for i, h := range c.hyps {
		if h.variant != variant {
			continue
		}
		id := HypothesisID(i + 1) //nolint:gosec // G115: a handful of hypotheses per app
		targets = append(targets, Target{Hypothesis: id, Class: h.class, Path: c.file, SourceLine: h.source, SinkLine: h.sink})
		byID[id] = h
	}
	return targets, byID
}

// runVariant evaluates every hypothesis on one app variant through the
// reader path: Slicer.Build on the app's file, then Evaluate per slice,
// each call answered by store in mode (and by m when recording).
func runVariant(store *state.Store, mode state.Mode, tier Tier, c appCase, variant string, m model) (map[HypothesisID]Signal, error) {
	targets, byID := c.targets(variant)
	rep, err := variantSlicer(tier, filepath.Join(appsDir, c.app, variant)).Build(targets)
	if err != nil {
		return nil, err
	}
	if len(rep.Slices) != len(targets) {
		return nil, fmt.Errorf("%d of %d hypotheses sliced: %+v %+v", len(rep.Slices), len(targets), rep.NotScanned, rep.NotEvaluated)
	}
	got := map[HypothesisID]Signal{}
	for _, s := range rep.Slices {
		h := byID[s.Hypothesis]
		client, err := replayClient(storeSend(store, mode, func() ([]byte, error) { return m(h) }))
		if err != nil {
			return nil, err
		}
		sig, err := Evaluate(context.Background(), client, tier, s)
		if err != nil {
			return nil, err
		}
		got[s.Hypothesis] = sig
	}
	return got, nil
}

func variantSlicer(tier Tier, dir string) Slicer {
	r, err := redact.New()
	if err != nil {
		panic(err) // the built-in rules always compile
	}
	files := os.DirFS(dir)
	return Slicer{Redactor: r, Tier: tier, Read: func(p string) ([]byte, error) { return fs.ReadFile(files, p) }}
}

// replayClient is an OpenAI-compatible client with strict JSON schema
// output, the most common shape. Retries is 0: a retry would be another
// recording, and a fixture holds one answer per hypothesis.
func replayClient(send models.SendFunc) (*models.HTTP, error) {
	return models.NewHTTP(models.Options{
		Contract: "openai", Endpoint: "https://models.replay.invalid/v1", Model: replayModelName,
		Structured: models.StructuredSchema, MaxOutputTokens: 512, Send: send,
	})
}

// storeSend answers each call with state.Store.Respond, keyed by the hash
// of the exact request body, so any change to the system prompt, slice,
// schema or model misses the recording instead of replaying a stale one.
func storeSend(store *state.Store, mode state.Mode, call func() ([]byte, error)) models.SendFunc {
	return func(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
		body, err := store.Respond(mode, replayKey(c), call)
		if err != nil {
			return nil, err
		}
		return &gateway.Reply{ID: "replay", Status: 200, Body: body}, nil
	}
}

func replayKey(c gateway.Call) state.Key {
	sum := sha256.Sum256(c.Payload)
	return state.Key{
		ContentHash:   hex.EncodeToString(sum[:]),
		Model:         c.Model,
		PromptVersion: fmt.Sprintf("reader.v%d", PromptVersion),
	}
}

// synthesizedReply is what the fixtures record; no live model is called.
// A hypothesis on the vulnerable variant is answered vulnerable and a safe
// twin not_vulnerable, both citing the sink line, as expected.json implies.
func synthesizedReply(h appHypothesis) ([]byte, error) {
	verdict, confidence := answerNotVulnerable, 80
	if h.variant == variantVulnerable {
		verdict, confidence = answerVulnerable, 90
	}
	return chatCompletion(Answer{Verdict: verdict, Evidence: []Evidence{{Start: h.sink, End: h.sink}}, Confidence: &confidence})
}

// chatCompletion wraps answer as an OpenAI-compatible reply body.
func chatCompletion(answer any) ([]byte, error) {
	content, err := json.Marshal(answer)
	if err != nil {
		return nil, err
	}
	message := map[string]any{"role": "assistant", "content": string(content)}
	return json.Marshal(map[string]any{
		"id": "chatcmpl-replay", "object": "chat.completion", "model": replayModelName,
		"choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": "stop"}},
		"usage":   map[string]int{"prompt_tokens": 0, "completion_tokens": len(content)},
	})
}

// copyFixtures copies an app's recordings into a fresh store directory.
func copyFixtures(t *testing.T, dir string) string {
	t.Helper()
	to := t.TempDir()
	if err := os.Mkdir(filepath.Join(to, "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range cacheFiles(t, dir) {
		data, err := os.ReadFile(filepath.Join(dir, "cache", name))
		if err != nil {
			t.Fatal(err)
		}
		// G703: name was listed from the fixture directory by cacheFiles.
		if err := os.WriteFile(filepath.Join(to, "cache", name), data, 0o600); err != nil { //nolint:gosec
			t.Fatal(err)
		}
	}
	return to
}

// cacheFiles lists the recordings of the store in dir.
func cacheFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatalf("no fixtures in %s (run go test ./internal/reader -run TestAppsReplay -update): %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	return names
}
