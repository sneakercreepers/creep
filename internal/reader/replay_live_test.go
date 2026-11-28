package reader

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/gateway/gatewaytest"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/state"
)

// liveTier is the tier the live recording covers (#356): the pinned
// qwen2.5-coder:1.5b of the live-record workflow lands at S and is unfit
// (ADR 0036), so it can honestly answer only the tier-S prompt. M and L
// stay synthesized until a model that calibrates there is recorded.
const liveTier = TierS

const liveNote = "Recorded live from the pinned Ollama model by .github/workflows/live-record.yml through the gateway (egress.log, redaction); " +
	"reply bodies normalized by gatewaytest.Normalize (message content byte for byte, no response ID). " +
	"Outcomes are what the model answered, not expected.json: the model is unfit (ADR 0036)." + liveVaries

// liveVaries is said in every live header: a rerun answers differently.
const liveVaries = " Live replies vary between runs of the same pinned model (the committed reader run agreed with expected.json on 7 of 18, a rerun on 9 of 18): the committed run is the reviewed one."

const synthesizedNote = "Synthesized from expected.json by synthesizedReply, not a model's judgement: no model that calibrates at this tier has been recorded (#356)."

func provenancePath(tier Tier) string {
	return filepath.Join(replayDir, strings.ToLower(string(tier)), "provenance.json")
}

func tierProvenance(t *testing.T, tier Tier) gatewaytest.Provenance {
	t.Helper()
	p, err := gatewaytest.ReadProvenance(provenancePath(tier))
	if err != nil {
		t.Fatal(err)
	}
	if p.Tier != string(tier) || (p.Synthesized && p.Model != replayModelName) {
		t.Fatalf("provenance of tier %s names tier %s, model %q", tier, p.Tier, p.Model)
	}
	return p
}

// writeSynthesizedProvenance is the header -update writes for a tier it
// synthesized.
func writeSynthesizedProvenance(t *testing.T, tier Tier) {
	t.Helper()
	p := gatewaytest.SynthesizedProvenance(replayModelName, string(tier), synthesizedNote)
	if err := gatewaytest.WriteProvenance(provenancePath(tier), p); err != nil {
		t.Fatal(err)
	}
}

// recordLiveTier records every app at tier from the live model, replacing
// the tier's recordings, and writes the header with what it answered.
func recordLiveTier(t *testing.T, tier Tier, live gatewaytest.LiveSettings) {
	send := gatewaytest.Live(t, live)
	outcomes := map[string]string{}
	for _, c := range appCases {
		dir := fixtureDir(tier, c.app)
		if err := os.RemoveAll(filepath.Join(dir, "cache")); err != nil {
			t.Fatal(err)
		}
		store := openStore(t, dir, fixtureSecret)
		maps.Copy(outcomes, liveOutcomes(t, store, state.ModeRecord, tier, c, live.Endpoint, live.Model, send))
	}
	logAgreement(t, tier, outcomes)
	p := gatewaytest.LiveProvenance(live, string(tier), liveNote, outcomes)
	if err := gatewaytest.WriteProvenance(provenancePath(tier), p); err != nil {
		t.Fatal(err)
	}
}

// replayLiveTier replays every app at a live tier, offline, and requires
// exactly the outcomes the recording header holds.
func replayLiveTier(t *testing.T, tier Tier, p gatewaytest.Provenance) {
	refuse := func(context.Context, gateway.Call) (*gateway.Reply, error) {
		return nil, errors.New("replay must not call the model")
	}
	got := map[string]string{}
	for _, c := range appCases {
		store := openStore(t, copyFixtures(t, fixtureDir(tier, c.app)), fixtureSecret)
		maps.Copy(got, liveOutcomes(t, store, state.ModeReplay, tier, c, replayEndpoint, p.Model, refuse))
		if n := len(cacheFiles(t, fixtureDir(tier, c.app))); n != len(c.hyps) {
			t.Fatalf("%s: %d fixture files for %d hypotheses", c.app, n, len(c.hyps))
		}
	}
	if !maps.Equal(got, p.Outcomes) {
		t.Fatalf("live tier %s replays to\n%v\nthe header recorded\n%v", tier, got, p.Outcomes)
	}
	logAgreement(t, tier, got)
}

// liveOutcomes evaluates both variants of c and returns each hypothesis's
// outcome. A store or send failure fails the test: only the model's own
// answer, valid or not, is an outcome.
func liveOutcomes(t *testing.T, store *state.Store, mode state.Mode, tier Tier, c appCase, endpoint, name string, live models.SendFunc) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, variant := range []string{variantVulnerable, variantSafe} {
		cut, byID, err := sliceVariant(tier, c, variant)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range cut {
			var failed error
			client, err := clientFor(endpoint, name, liveStoreSend(store, mode, live, &failed))
			if err != nil {
				t.Fatal(err)
			}
			sig, err := Evaluate(context.Background(), client, tier, s)
			if failed != nil {
				t.Fatalf("%s %s: %v", c.app, variant, failed)
			}
			out[byID[s.Hypothesis].key(c.app)] = outcomeOf(sig, err)
		}
	}
	return out
}

// liveStoreSend is storeSend with the live model behind it: a recording
// answers each call from live, a replay from the store alone. failed
// keeps the store's or the model's error.
func liveStoreSend(store *state.Store, mode state.Mode, live models.SendFunc, failed *error) models.SendFunc {
	return func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
		body, err := store.Respond(mode, replayKey(c), func() ([]byte, error) {
			r, err := live(ctx, c)
			if err != nil {
				return nil, err
			}
			return r.Body, nil
		})
		if err != nil {
			*failed = err
			return nil, err
		}
		return &gateway.Reply{ID: "replay", Status: 200, Body: body}, nil
	}
}

func (h appHypothesis) key(app string) string {
	return fmt.Sprintf("%s/%s/%s %s", app, h.variant, h.class, h.route)
}

var verdictNames = map[Verdict]string{
	VerdictInconclusive: answerInconclusive, VerdictNotVulnerable: answerNotVulnerable, VerdictVulnerable: answerVulnerable,
}

// outcomeOf names a verdict with its evidence and confidence, or the kind
// of answer the reader refused.
func outcomeOf(sig Signal, err error) string {
	switch {
	case errors.Is(err, ErrEvidence):
		return "refused: evidence outside the slice"
	case err != nil:
		return "refused: invalid answer"
	}
	var lines []string
	for _, r := range sig.Evidence {
		lines = append(lines, fmt.Sprintf("%d-%d", r.Start, r.End))
	}
	return fmt.Sprintf("%s lines [%s] confidence %d", verdictNames[sig.Verdict], strings.Join(lines, " "), sig.Confidence)
}

// logAgreement logs how many outcomes match what expected.json implies:
// information about the model, never a failure.
func logAgreement(t *testing.T, tier Tier, outcomes map[string]string) {
	t.Helper()
	agree := 0
	for key, o := range outcomes {
		vulnerable := strings.Contains(key, "/"+variantVulnerable+"/")
		if (vulnerable && strings.HasPrefix(o, answerVulnerable)) || (!vulnerable && strings.HasPrefix(o, answerNotVulnerable)) {
			agree++
		}
	}
	t.Logf("tier %s: %d of %d live verdicts agree with expected.json", tier, agree, len(outcomes))
}

// No committed reply holds an endpoint, a key, a provider response ID or a
// routing field (#356), and every tier says whether it is live.
func TestReplayFixturesHoldNoProviderData(t *testing.T) {
	for _, tier := range replayTiers {
		tierProvenance(t, tier)
		for _, c := range appCases {
			dir := fixtureDir(tier, c.app)
			for _, name := range cacheFiles(t, dir) {
				if err := gatewaytest.CheckStoreRecording(filepath.Join(dir, "cache", name)); err != nil {
					t.Errorf("%s %s: %v", dir, name, err)
				}
			}
		}
	}
}
