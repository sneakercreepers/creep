package calibrate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The floors read only the planned classes: their 64 tasks need 40 right
// (Wilson lower bound 0.503) and at most half of their 32 safe twins
// flagged.
func TestAssessFitness(t *testing.T) {
	flag := func(r *Result, i, n int) {
		c := &r.Classes[i]
		c.SafeFlagged += n
		c.Score = newScore(c.Correct-n, c.Total)
	}
	tests := []struct {
		name   string
		edit   func(r *Result)
		reason UnfitReason
	}{
		{"perfect", func(*Result) {}, ""},
		{"40 of 64 right is above chance", func(r *Result) { missVulnerable(r, map[int]int{0: 4, 1: 4, 2: 4, 3: 4, 4: 4, 5: 4}) }, ""},
		{"39 of 64 right is not", func(r *Result) { missVulnerable(r, map[int]int{0: 4, 1: 4, 2: 4, 3: 4, 4: 4, 5: 4, 6: 1}) }, UnfitBelowChance},
		{"half the safe twins flagged passes", func(r *Result) { flag(r, 0, 4); flag(r, 2, 4); flag(r, 5, 4); flag(r, 7, 4) }, ""},
		{"most safe twins flagged", func(r *Result) { flag(r, 0, 4); flag(r, 2, 4); flag(r, 5, 4); flag(r, 7, 4); flag(r, 6, 1) }, UnfitFlagsSafeTwins},
		{"every twin flagged, every vulnerable task right", func(r *Result) {
			for i := range PlannedClasses() {
				flag(r, i, r.Classes[i].SafeTwins)
			}
		}, UnfitBelowChance},
		{"no safe twins", func(r *Result) {
			for i := range r.Classes {
				r.Classes[i].SafeTwins = 0
			}
		}, UnfitFlagsSafeTwins},
		{"class missing", func(r *Result) { r.Classes = r.Classes[1:] }, UnfitBelowChance},
		{"zero result", func(r *Result) { *r = Result{} }, UnfitBelowChance},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := perfectResult()
			tt.edit(&r)
			f := assessFitness(r)
			if f.Fit != (tt.reason == "") || f.Reason != tt.reason {
				t.Errorf("fitness %+v, want reason %q", f, tt.reason)
			}
		})
	}
}

// Protection (#363): a replayed model that answers "vulnerable" to every
// task, with the right class and line wherever there is one, calibrates
// unfit and is refused with the measured numbers. The cache records the
// verdict, so the next lookup refuses it again with no model call.
func TestUnfitModelRefused(t *testing.T) {
	e := newCacheEnv(t)
	e.model = answering(func(user string) string {
		if task, ok := e.o.task(user); ok && !task.Vulnerable {
			return taskJSON(true, string(task.Class), task.Line)
		}
		return e.o.answer(user)
	})
	for i, wantCalls := range []bool{true, false} {
		c, calls := e.run(t, e.options(t, calibrated.Add(time.Duration(i)*time.Hour)))
		if (calls > 0) != wantCalls || c.Cached == wantCalls {
			t.Fatalf("lookup %d: calls %d, cached %v", i, calls, c.Cached)
		}
		err := c.CheckFit()
		var unfit *UnfitError
		if !errors.Is(err, ErrUnfit) || !errors.As(err, &unfit) || unfit.Fitness.Reason != UnfitBelowChance {
			t.Fatalf("lookup %d: CheckFit = %v", i, err)
		}
		for _, want := range []string{"model unfit", "32 of 64", "32 of 32 safe twins", "--allow-unfit-model"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q lacks %q", err, want)
			}
		}
		if !strings.Contains(c.Header(), "UNFIT (below_chance") {
			t.Errorf("header %q does not mark the model unfit", c.Header())
		}
	}
}

// The recorded tier-M model is fit: the floor leaves a fit model alone.
// Its two safe twins not called safe are the template_injection twin it
// flagged and the ssrf twin it answered invalidly twice.
func TestFixtureModelIsFit(t *testing.T) {
	rep, _ := fromFixture(t, "seed1_tier_m")
	r, err := Run(context.Background(), testOptions(t, 1, rep.send))
	if err != nil {
		t.Fatal(err)
	}
	want := Fitness{Fit: true, Planned: ClassScore{Score: newScore(59, 64), SafeTwins: 32, SafeFlagged: 2}}
	if !r.Fitness.sameVerdict(want) {
		t.Errorf("fitness %+v, want %+v", r.Fitness, want)
	}
	if err := (Calibration{Result: r}).CheckFit(); err != nil {
		t.Errorf("CheckFit = %v", err)
	}
}

func TestClassScoreConsistent(t *testing.T) {
	tests := []struct {
		name string
		s    ClassScore
		ok   bool
	}{
		{"perfect", ClassScore{Score: Score{Correct: 14, Total: 14}, SafeTwins: 7}, true},
		{"every twin flagged", ClassScore{Score: Score{Correct: 7, Total: 14}, SafeTwins: 7, SafeFlagged: 7}, true},
		{"more flagged than twins", ClassScore{Score: Score{Correct: 0, Total: 14}, SafeTwins: 7, SafeFlagged: 8}, false},
		{"clean twins not counted right", ClassScore{Score: Score{Correct: 6, Total: 14}, SafeTwins: 7}, false},
		{"more right than vulnerable tasks", ClassScore{Score: Score{Correct: 14, Total: 14}, SafeTwins: 7, SafeFlagged: 1}, false},
		{"more twins than tasks", ClassScore{Score: Score{Correct: 2, Total: 2}, SafeTwins: 3}, false},
		{"negative flagged", ClassScore{Score: Score{Correct: 14, Total: 14}, SafeTwins: 7, SafeFlagged: -1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.consistent(); got != tt.ok {
				t.Errorf("consistent = %v, want %v", got, tt.ok)
			}
		})
	}
}
