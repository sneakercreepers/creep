package discover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/gateway/gatewaytest"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/state"
)

// liveSmallFixture is the pinned Ollama model's live discovery batch on
// the flask app at tier S (#356), recorded by
// .github/workflows/live-record.yml; provenance.json beside it names the
// model, digest, date and run, and what the batch replays to.
const liveSmallFixture = "testdata/replay/live-s/flask"

const liveSmallNote = "Recorded live from the pinned Ollama model by .github/workflows/live-record.yml through the gateway (egress.log, redaction), " +
	"Discoverer.Run at tier S with testSeed on testdata/apps/flask/vulnerable; reply bodies normalized by gatewaytest.Normalize. " +
	"Outcomes are what the model's batch gave, not the app's ground truth: the model is unfit (ADR 0036). Live replies vary between runs of the same pinned model: the committed run is the reviewed one."

// Acceptance (#356): the live small-model batch replays offline, with no
// model call, to exactly what the recording gave. -update re-records it
// only with CREEP_LIVE_ENDPOINT and CREEP_LIVE_MODEL set.
func TestLiveSmallModelReplay(t *testing.T) {
	live, recording, err := gatewaytest.LiveFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	app := loadApp(t, "flask")
	if *update && recording {
		recordLiveSmall(t, app, live)
	}
	p, err := gatewaytest.ReadProvenance(filepath.Join(liveSmallFixture, "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Synthesized || p.Tier != string(TierS) {
		t.Fatalf("provenance: synthesized %v, tier %s; this fixture is live, tier S", p.Synthesized, p.Tier)
	}
	store := openFixtureStore(t, copyFixtures(t, liveSmallFixture))
	refuse := func(context.Context, gateway.Call) (*gateway.Reply, error) {
		return nil, errors.New("replay must not call the model")
	}
	got := liveSmallOutcomes(t, app, store, state.ModeReplay, "https://models.replay.invalid/v1", p.Model, refuse)
	if !maps.Equal(got, p.Outcomes) {
		t.Fatalf("live batch replays to\n%v\nthe header recorded\n%v", got, p.Outcomes)
	}
}

// recordLiveSmall replaces the fixture with a live recording and writes
// its header.
func recordLiveSmall(t *testing.T, app testApp, live gatewaytest.LiveSettings) {
	t.Helper()
	if err := os.RemoveAll(filepath.Join(liveSmallFixture, "cache")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(liveSmallFixture, 0o700); err != nil {
		t.Fatal(err)
	}
	store := openFixtureStore(t, liveSmallFixture)
	outcomes := liveSmallOutcomes(t, app, store, state.ModeRecord, live.Endpoint, live.Model, gatewaytest.Live(t, live))
	p := gatewaytest.LiveProvenance(live, string(TierS), liveSmallNote, outcomes)
	if err := gatewaytest.WriteProvenance(filepath.Join(liveSmallFixture, "provenance.json"), p); err != nil {
		t.Fatal(err)
	}
}

func openFixtureStore(t *testing.T, dir string) *state.Store {
	t.Helper()
	store, err := state.OpenWithSecret(dir, fixtureSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// liveSmallOutcomes runs the batch through store and names what it gave.
// A store or send failure fails the test: only the model's answer, valid
// or not, is an outcome.
func liveSmallOutcomes(t *testing.T, app testApp, store *state.Store, mode state.Mode, endpoint, name string, live models.SendFunc) map[string]string {
	t.Helper()
	var failed error
	send := func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
		sum := sha256.Sum256(c.Payload)
		key := state.Key{ContentHash: hex.EncodeToString(sum[:]), Model: c.Model, PromptVersion: fmt.Sprintf("discover.v%d", PromptVersion)}
		body, err := store.Respond(mode, key, func() ([]byte, error) {
			r, err := live(ctx, c)
			if err != nil {
				return nil, err
			}
			return r.Body, nil
		})
		if err != nil {
			failed = err
			return nil, err
		}
		return &gateway.Reply{ID: "replay", Status: 200, Body: body}, nil
	}
	res, err := smallDiscoverer(t, app, endpoint, name, send).Run(context.Background(), []string{app.file})
	if failed != nil {
		t.Fatal(failed)
	}
	return discoveryOutcomes(res, err)
}

// discoveryOutcomes names a Result by its IDs, enums and lines only.
func discoveryOutcomes(res Result, err error) map[string]string {
	out := map[string]string{
		"error":    fmt.Sprint(err != nil),
		"complete": fmt.Sprint(res.Complete()),
		"routes":   fmt.Sprint(len(res.Routes)),
		"sinks":    fmt.Sprint(len(res.Sinks)),
	}
	for _, f := range res.Files {
		out[fmt.Sprintf("file %d", f.ID)] = fmt.Sprintf("coverage %v reason %v", f.Coverage, f.Reason)
	}
	for _, s := range res.Sinks {
		out[fmt.Sprintf("sink %d", s.ID)] = fmt.Sprintf("line %d kind %v origin %v", s.Line, s.Kind, s.Origin)
	}
	return out
}

// No committed discovery reply holds an endpoint, a key, a provider
// response ID or a routing field (#356).
func TestDiscoverFixturesHoldNoProviderData(t *testing.T) {
	n := 0
	err := filepath.WalkDir("testdata/replay", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Base(filepath.Dir(path)) != "cache" || filepath.Ext(path) != ".json" {
			return err
		}
		n++
		return gatewaytest.CheckStoreRecording(path)
	})
	if err != nil || n == 0 {
		t.Fatalf("%d recordings checked: %v", n, err)
	}
}
