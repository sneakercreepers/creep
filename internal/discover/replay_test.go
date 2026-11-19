package discover

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/state"
)

var (
	update = flag.Bool("update", false, "rewrite the replay fixtures in testdata/replay from the synthesized model")
	// fixtures lets a store recorded from a real model be scored by the
	// same replay and recall tests (ADR 0017 F2): point it at a directory
	// holding <app>/cache, recorded with replayModel, replayTier and
	// testSeed through Discoverer.Run.
	fixtures    = flag.String("fixtures", "testdata/replay", "directory of per-app replay stores to replay and score")
	replayModel = flag.String("replay-model", replayModelName, "model name the fixtures were recorded with")
)

const (
	appsDir           = "../../testdata/apps"
	variantVulnerable = "vulnerable"
	replayTier        = TierM
)

// fixtureSecret signs the committed fixtures. It is a fixed, public test
// value: a real run opens its store with the user's own secret, so a
// recording signed with this one is never served outside tests.
var fixtureSecret = bytes.Repeat([]byte{0x5a}, state.SecretBytes)

// Acceptance (#265 step B): every testdata app's vulnerable variant
// replays through Discoverer.Run from its committed fixture, with no
// network, no key and no model call, to a complete Result. Regenerate:
// go test ./internal/discover -run TestAppsReplay -update
func TestAppsReplay(t *testing.T) {
	for _, app := range testApps(t) {
		t.Run(app.name, func(t *testing.T) {
			res := replayApp(t, app)
			if !res.Complete() {
				t.Fatalf("replayed run is incomplete: %+v", res.Files)
			}
			if n := len(cacheFiles(t, filepath.Join(*fixtures, app.name))); n != 1 {
				t.Fatalf("%d fixture files, want one batch; rerun with -update", n)
			}
		})
	}
}

// replayApp runs discovery on an app's vulnerable variant from its store:
// recording from the synthesized model with -update, replaying otherwise.
func replayApp(t *testing.T, app testApp) Result {
	t.Helper()
	store, mode := fixtureStore(t, app.name)
	calls := 0
	model := func(prompt string) ([]byte, error) {
		calls++
		if !*update {
			return nil, errors.New("replay must not call the model")
		}
		return synthesizedReply(app, parseSections(prompt))
	}
	files := os.DirFS(filepath.Join(appsDir, app.name, variantVulnerable))
	d := Discoverer{
		Redactor: newRedactor(t), Model: replayClient(t, storeSend(store, mode, model)), Tier: replayTier, Seed: testSeed,
		Read: func(p string) ([]byte, error) { return fs.ReadFile(files, p) },
	}
	res, err := d.Run(context.Background(), []string{app.file})
	if err != nil {
		t.Fatal(err)
	}
	if !*update && calls != 0 {
		t.Fatalf("replay made %d model calls", calls)
	}
	return res
}

func replayClient(t *testing.T, send models.SendFunc) *models.HTTP {
	t.Helper()
	h, err := models.NewHTTP(models.Options{
		Contract: "openai", Endpoint: "https://models.replay.invalid/v1", Model: *replayModel,
		Structured: models.StructuredSchema, MaxOutputTokens: 4096, Send: send,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// storeSend answers each call with state.Store.Respond, keyed by the hash
// of the exact request body, so any change to a prompt, the schema, the
// canary, the batch layout or an app misses the recording instead of
// replaying a stale one.
func storeSend(store *state.Store, mode state.Mode, model func(prompt string) ([]byte, error)) models.SendFunc {
	return func(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
		sum := sha256.Sum256(c.Payload)
		key := state.Key{ContentHash: hex.EncodeToString(sum[:]), Model: c.Model, PromptVersion: fmt.Sprintf("discover.v%d", PromptVersion)}
		body, err := store.Respond(mode, key, func() ([]byte, error) {
			prompt, err := userTurn(c.Payload)
			if err != nil {
				return nil, err
			}
			content, err := model(prompt)
			if err != nil {
				return nil, err
			}
			return chatCompletion(content)
		})
		if err != nil {
			return nil, err
		}
		return &gateway.Reply{ID: "replay", Status: 200, Body: body}, nil
	}
}

// fixtureStore opens the app's store. With -update it records into the
// fixtures directory, dropping old recordings first; otherwise it replays
// a copy, so the test never writes into the repository.
func fixtureStore(t *testing.T, app string) (*state.Store, state.Mode) {
	t.Helper()
	dir := filepath.Join(*fixtures, app)
	mode := state.ModeReplay
	if *update {
		if err := os.RemoveAll(filepath.Join(dir, "cache")); err != nil {
			t.Fatal(err)
		}
		mode = state.ModeRecord
	} else {
		dir = copyFixtures(t, dir)
	}
	store, err := state.OpenWithSecret(dir, fixtureSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, mode
}

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

func cacheFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatalf("no fixtures in %s (run go test ./internal/discover -run TestAppsReplay -update): %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	return names
}

// A missing or edited recording fails the replay instead of calling out.
func TestReplayFailsClosed(t *testing.T) {
	app := testApps(t)[0]
	store, err := state.OpenWithSecret(t.TempDir(), fixtureSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	d := Discoverer{
		Redactor: newRedactor(t), Tier: replayTier, Seed: testSeed,
		Model: replayClient(t, storeSend(store, state.ModeReplay, func(string) ([]byte, error) {
			return nil, errors.New("replay must not call the model")
		})),
		Read: func(p string) ([]byte, error) {
			return os.ReadFile(filepath.Join(appsDir, app.name, variantVulnerable, p))
		},
	}
	res, err := d.Run(context.Background(), []string{app.file})
	if !errors.Is(err, state.ErrNotRecorded) || res.Complete() || res.Files[0].Reason != ReasonSendFailed {
		t.Fatalf("err = %v, file %+v; want ErrNotRecorded and send_failed", err, res.Files[0])
	}
}
