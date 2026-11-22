package discover

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

// stabilityRun discovers flaskApp with one model per sample, at tier M.
func stabilityRun(t *testing.T, samples ...replyFunc) (Result, error) {
	t.Helper()
	d := Discoverer{
		Redactor: newRedactor(t), Model: fakeClient(t, samples[0], nil), Tier: TierM, Seed: testSeed,
		Read: func(string) ([]byte, error) { return []byte(flaskApp), nil },
	}
	for _, reply := range samples[1:] {
		d.Reruns = append(d.Reruns, fakeClient(t, reply, nil))
	}
	return d.Run(context.Background(), []string{"app.py"})
}

// withoutCanary is a valid reply that names the app's SQL sink but not
// the canary.
func withoutCanary(secs []promptSection) ([]byte, error) {
	c, _ := canaryOf(secs)
	return fmt.Appendf(nil, `{"entries":[],"sinks":[{"file":%d,"line":6,"kind":"sql","entry":-1}],"auth":[]}`, 1-c.section), nil
}

// Protection (#37, ADR 0024): stability is union only. Whatever a rerun
// answers (nothing, another sink, an invalid reply, no canary) every
// candidate of every sample is kept at the planner's worst case, Seen
// counts the samples that named it (all of them for a tripwire hit), and a
// file any sample failed stays failed: a rerun never removes a candidate,
// lowers its risk or clears a failure.
func TestStabilityNeverDropsCandidates(t *testing.T) {
	template := withApp(rawReply{sinks: `{"file":N,"line":1,"kind":"template","entry":-1}`})
	shell := withApp(rawReply{sinks: `{"file":N,"line":2,"kind":"shell","entry":-1}`})
	tests := []struct {
		name     string
		samples  []replyFunc
		seen     map[SinkKind]uint8 // every sink the Result must hold
		coverage Coverage
	}{
		{"rerun proposes nothing", []replyFunc{template, withApp(rawReply{})},
			map[SinkKind]uint8{SinkTemplate: 1, SinkSQL: 2}, CoverageReadFull},
		{"rerun proposes another sink", []replyFunc{template, shell, template},
			map[SinkKind]uint8{SinkTemplate: 2, SinkShell: 1, SinkSQL: 3}, CoverageReadFull},
		{"rerun reply invalid", []replyFunc{template, withApp(rawReply{top: `{"entries":[]}`})},
			map[SinkKind]uint8{SinkTemplate: 1, SinkSQL: 2}, CoverageSendFailed},
		{"rerun misses the canary", []replyFunc{template, withoutCanary},
			map[SinkKind]uint8{SinkTemplate: 1, SinkSQL: 2}, CoverageCanaryMissed},
		{"first sample misses the canary", []replyFunc{withoutCanary, template},
			map[SinkKind]uint8{SinkTemplate: 1, SinkSQL: 2}, CoverageCanaryMissed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := stabilityRun(t, tt.samples...)
			if err != nil {
				t.Fatal(err)
			}
			if int(res.Samples) != len(tt.samples) {
				t.Errorf("Samples = %d, want %d", res.Samples, len(tt.samples))
			}
			if f := fileOf(t, res, 0); f.Coverage != tt.coverage {
				t.Errorf("file = %+v, want coverage %d", f, tt.coverage)
			}
			got := map[SinkKind]uint8{}
			for _, s := range res.Sinks {
				got[s.Kind] = uint8(s.Seen()) //nolint:gosec // G115: at most MaxSamples
				if !s.DynamicArg || s.Parameterized || s.Indirect {
					t.Errorf("sink %+v: a rerun lowered its risk", s)
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.seen) {
				t.Errorf("sinks seen = %v, want %v", got, tt.seen)
			}
		})
	}
}

// Every sample gets every batch with the same prompt, and a sample whose
// call fails with a stopping error stops the model path as Model's would.
func TestRerunsSendEveryBatch(t *testing.T) {
	files, paths := smallFiles(MaxFilesPerBatch + 2) // two batches
	var first, second []string
	d := Discoverer{
		Redactor: newRedactor(t), Model: fakeClient(t, honestReply, &first), Tier: TierM, Seed: testSeed,
		Reruns: []*models.HTTP{fakeClient(t, honestReply, &second)},
		Read:   func(p string) ([]byte, error) { return []byte(files[p]), nil },
	}
	res, err := d.Run(context.Background(), paths)
	if err != nil || !res.Complete() {
		t.Fatalf("err %v, complete %v", err, res.Complete())
	}
	if len(first) != 2 || fmt.Sprint(first) != fmt.Sprint(second) {
		t.Fatalf("model got %d prompts, rerun %d; want the same two", len(first), len(second))
	}
	for _, s := range res.Sinks {
		if s.SeenBy != 0b11 {
			t.Errorf("tripwire sink %+v: want both samples", s)
		}
	}

	budget := fmt.Errorf("send: %w", gateway.ErrBudgetExhausted)
	d.Reruns = []*models.HTTP{fakeClient(t, func([]promptSection) ([]byte, error) { return nil, budget }, nil)}
	first = nil
	res, err = d.Run(context.Background(), paths)
	if !errors.Is(err, gateway.ErrBudgetExhausted) || !res.Incomplete || len(first) != 1 {
		t.Fatalf("err %v, incomplete %v after %d calls; a rerun's budget error must stop the run", err, res.Incomplete, len(first))
	}
	for _, f := range res.Files {
		if f.Coverage != CoverageSendFailed || f.Reason != ReasonBudget {
			t.Errorf("file %+v, want send_failed budget", f)
		}
	}
	if len(res.Sinks) != len(paths) {
		t.Errorf("%d sinks, want every tripwire hit kept", len(res.Sinks))
	}
}
