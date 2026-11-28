package calibrate

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/gateway/gatewaytest"
)

// liveFixture is a live calibration of seed 1 by the pinned Ollama model
// (#356, the #377 audit), recorded by .github/workflows/live-record.yml.
// Its provenance file names the model, digest, date and run, and the
// Result the replies replay to, whatever tier and fitness that is.
const liveFixture = "live_seed1"

const liveCalibrationNote = "Recorded live from the pinned Ollama model by .github/workflows/live-record.yml through the gateway (egress.log, redaction): " +
	"calibrate.Run with seed 1 and the test client settings; reply bodies normalized by gatewaytest.Normalize. " +
	"Outcomes are the Result the model earned, unfit included (ADR 0036). Live replies vary between runs of the same pinned model: the committed run is the reviewed one."

func liveProvenancePath() string {
	return filepath.Join("testdata", "replay", liveFixture+".provenance.json")
}

// Acceptance (#356): the live calibration replays offline, twice the
// same, to the Result recorded in its header. -update re-records it only
// with CREEP_LIVE_ENDPOINT and CREEP_LIVE_MODEL set.
func TestLiveCalibrationReplay(t *testing.T) {
	live, recording, err := gatewaytest.LiveFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if *updateFixtures && recording {
		recordLiveCalibration(t, live)
	}
	p, err := gatewaytest.ReadProvenance(liveProvenancePath())
	if err != nil {
		t.Fatal(err)
	}
	if p.Synthesized {
		t.Fatal("the live calibration fixture says it is synthesized")
	}
	var first Result
	for i := range 2 {
		rep, n := fromFixture(t, liveFixture)
		r, err := Run(context.Background(), Options{Seed: 1, Model: newModelFor(t, "https://models.invalid/v1", p.Model, rep.send), Redactor: newRedactor(t)})
		if err != nil {
			t.Fatal(err)
		}
		if rep.replies != n || len(rep.calls) != n {
			t.Fatalf("run used %d of %d recorded replies in %d calls", rep.replies, n, len(rep.calls))
		}
		if i == 1 && !reflect.DeepEqual(r, first) {
			t.Fatalf("replay differs:\n%+v\n%+v", r, first)
		}
		first = r
	}
	if got := calibrationOutcomes(t, first); !maps.Equal(got, p.Outcomes) || string(first.Tier) != p.Tier {
		t.Fatalf("live calibration replays to tier %s\n%v\nthe header recorded tier %s\n%v", first.Tier, got, p.Tier, p.Outcomes)
	}
}

// recordLiveCalibration runs one calibration against the live model,
// writes every reply in call order and the header with its Result.
func recordLiveCalibration(t *testing.T, live gatewaytest.LiveSettings) {
	t.Helper()
	send := gatewaytest.Live(t, live)
	var recs []recordedReply
	record := func(ctx context.Context, call gateway.Call) (*gateway.Reply, error) {
		reply, err := send(ctx, call)
		if err == nil {
			recs = append(recs, recordedReply{Request: payloadHash(call.Payload), Status: reply.Status, Body: reply.Body})
		}
		return reply, err
	}
	r, err := Run(context.Background(), Options{Seed: 1, Model: newModelFor(t, live.Endpoint, live.Model, record), Redactor: newRedactor(t)})
	if err != nil {
		t.Fatal(err)
	}
	writeReplayFile(t, liveFixture, recs)
	p := gatewaytest.LiveProvenance(live, string(r.Tier), liveCalibrationNote, calibrationOutcomes(t, r))
	if err := gatewaytest.WriteProvenance(liveProvenancePath(), p); err != nil {
		t.Fatal(err)
	}
}

// calibrationOutcomes is r as its top-level JSON fields: numbers, enums
// and hashes only.
func calibrationOutcomes(t *testing.T, r Result) map[string]string {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for k, v := range fields {
		out[k] = string(v)
	}
	return out
}

// No committed calibration reply holds an endpoint, a key, a provider
// response ID or a routing field (#356).
func TestCalibrationFixturesHoldNoProviderData(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("testdata", "replay", "*.json"))
	if err != nil || len(names) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, name := range names {
		if strings.HasSuffix(name, ".provenance.json") {
			continue
		}
		p, err := gatewaytest.ReadProvenance(strings.TrimSuffix(name, ".json") + ".provenance.json")
		if err != nil {
			t.Fatalf("%s has no header: %v", name, err)
		}
		if p.Synthesized == (filepath.Base(name) == liveFixture+".json") {
			t.Errorf("%s: header says synthesized %v", name, p.Synthesized)
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var recs []recordedReply
		if err := json.Unmarshal(data, &recs); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i, rec := range recs {
			if err := gatewaytest.CheckReplyHygiene(rec.Body); err != nil {
				t.Errorf("%s reply %d: %v", name, i, err)
			}
		}
	}
}
