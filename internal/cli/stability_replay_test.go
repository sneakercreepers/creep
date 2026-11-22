package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/state"
	"github.com/sneakercreepers/creep/internal/verify"
)

const stabilityReplayDir = "testdata/replay/stability"

// stabilityAnswers are the synthesized model's answers, one per sample,
// to the Flask app's first SQL injection: the replayed samples disagree.
var stabilityAnswers = []string{"vulnerable", "not_vulnerable", "vulnerable"}

// #37 (AGENTS.md: new model behavior needs a replay fixture): three
// samples of one hypothesis replay from the committed fixture, through the
// reader's real slice of a testdata app, the scan's own cache key and each
// sample's label, with no network and no model call, to the same verdict
// and votes: probable, seen by samples 1 and 3. A change to how samples
// are labeled or keyed misses the fixture and fails here.
// Regenerate with: go test ./internal/cli -run TestStabilityReaderReplay -update
func TestStabilityReaderReplay(t *testing.T) {
	store, mode := stabilityFixtureStore(t)
	calls := 0
	synth := newSampledModel(stabilityAnswers...)
	live := func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
		calls++
		if !*updateGolden {
			return nil, errors.New("replay must not call the model")
		}
		return synth.send(ctx, c)
	}
	newModel := func(k int) (*models.HTTP, error) {
		m := config.Model{Contract: "openai", Endpoint: "https://models.replay.invalid/v1", Name: pocReplayModel}
		return models.NewHTTP(modelOptions(m, models.Key{}, sampleSend(k, recordedSend(store, mode, live))))
	}
	first, err := newModel(1)
	if err != nil {
		t.Fatal(err)
	}
	reruns, err := rerunModels(len(stabilityAnswers), newModel)
	if err != nil {
		t.Fatal(err)
	}
	c := pocCases[0]
	stage := readStage{model: first, reruns: reruns, tier: reader.Tier(verify.TierM), votes: map[int]uint8{}}
	f := report.Finding{ID: "sink-1", Class: c.class, Status: report.StatusNotEvaluated, Path: c.target.Path, Line: c.target.SinkLine}
	if reason, stop := stage.evaluateSamples(context.Background(), pocSlice(t, verify.TierM, c.target), 0, &f); stop || reason != "" {
		t.Fatalf("stopped: %q", reason)
	}
	if f.Status != report.StatusProbable || stage.votes[0] != 0b101 {
		t.Fatalf("finding %s, votes %03b; want probable, samples 1 and 3", f.Status, stage.votes[0])
	}
	if !*updateGolden && calls != 0 {
		t.Fatalf("replay made %d model calls", calls)
	}
	if n := len(pocFixtureFiles(t, stabilityReplayDir)); n != len(stabilityAnswers) {
		t.Fatalf("%d fixture files for %d samples; rerun with -update", n, len(stabilityAnswers))
	}
}

// stabilityFixtureStore records into the fixture directory with -update,
// dropping old recordings first; otherwise it replays a copy, so the test
// never writes into the repository.
func stabilityFixtureStore(t *testing.T) (*state.Store, state.Mode) {
	t.Helper()
	dir, mode := stabilityReplayDir, state.ModeReplay
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
