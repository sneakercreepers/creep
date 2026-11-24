package bench

import (
	"strings"
	"testing"
)

// scoreCases are two sqli cases with the vulnerable sink on line 10.
func scoreCases() []Case {
	twins := map[Variant]Twin{Vulnerable: {Entry: 2, Sink: 10}, Safe: {Entry: 2, Sink: 11}}
	return []Case{
		{ID: "a", Class: "sqli", twins: twins},
		{ID: "b", Class: "sqli", twins: twins},
	}
}

// allRuns is every tier and twin of scoreCases, clean and claimed
// covered, with edit applied to each.
func allRuns(edit func(*Outcome)) []Outcome {
	var out []Outcome
	for _, tier := range Tiers() {
		for _, id := range []string{"a", "b"} {
			for _, v := range Variants() {
				o := Outcome{Tier: tier, Case: id, Variant: v, Covered: true}
				edit(&o)
				out = append(out, o)
			}
		}
	}
	return out
}

func flagged(class string, line int) []Finding {
	return []Finding{{Class: class, Line: line, Flagged: true}}
}

func TestScore(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Outcome)
		// want for tier S, class sqli: detected, false positives, claimed, silent misses
		detected, fps, claimed, silent int
	}{
		{"nothing found but claimed covered: silent misses", func(*Outcome) {}, 0, 0, 2, 2},
		{"found on the sink", func(o *Outcome) {
			if o.Variant == Vulnerable {
				o.Findings = flagged("sqli", 10)
			}
		}, 2, 0, 2, 0},
		{"two lines away still counts", func(o *Outcome) {
			if o.Variant == Vulnerable {
				o.Findings = flagged("sqli", 8)
			}
		}, 2, 0, 2, 0},
		{"three lines away misses", func(o *Outcome) {
			if o.Variant == Vulnerable {
				o.Findings = flagged("sqli", 13)
			}
		}, 0, 0, 2, 2},
		{"wrong class misses", func(o *Outcome) {
			if o.Variant == Vulnerable {
				o.Findings = flagged("ssrf", 10)
			}
		}, 0, 0, 2, 2},
		{"discarded finding misses", func(o *Outcome) {
			if o.Variant == Vulnerable {
				o.Findings = []Finding{{Class: "sqli", Line: 10}}
			}
		}, 0, 0, 2, 2},
		{"honest miss: not claimed covered", func(o *Outcome) { o.Covered = false }, 0, 0, 0, 0},
		{"any flagged class on a safe twin is a false positive", func(o *Outcome) {
			if o.Variant == Safe {
				o.Findings = flagged("command_injection", 3)
			}
		}, 0, 2, 2, 2},
		{"discarded finding on a safe twin is not", func(o *Outcome) {
			if o.Variant == Safe {
				o.Findings = []Finding{{Class: "sqli", Line: 11}}
			}
		}, 0, 0, 2, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tiers, err := Score(scoreCases(), allRuns(tc.edit))
			if err != nil {
				t.Fatal(err)
			}
			if len(tiers) != 3 || tiers[0].Tier != "S" || len(tiers[0].Classes) != 1 {
				t.Fatalf("tiers %+v", tiers)
			}
			r := tiers[0].Classes[0]
			if r.Vulnerable != 2 || r.Safe != 2 || r.Detected != tc.detected || r.FalsePositives != tc.fps ||
				r.ClaimedCovered != tc.claimed || r.SilentMisses != tc.silent {
				t.Fatalf("got %+v", r)
			}
			if (r.Honesty == nil) != (tc.claimed == 0) {
				t.Fatalf("honesty %v with %d claims: a rate over nothing must be null", r.Honesty, tc.claimed)
			}
		})
	}
}

func TestScoreRates(t *testing.T) {
	tiers, err := Score(scoreCases(), allRuns(func(o *Outcome) {
		if o.Case == "a" && o.Variant == Vulnerable {
			o.Findings = flagged("sqli", 10)
		}
		o.Incomplete = o.Case == "b"
	}))
	if err != nil {
		t.Fatal(err)
	}
	r := tiers[1].Classes[0]
	if *r.Recall != 0.5 || *r.FalsePositiveRate != 0 || *r.Honesty != 0.5 || tiers[1].IncompleteRuns != 2 || tiers[1].Runs != 4 {
		t.Fatalf("got %+v, tier %+v", r, tiers[1])
	}
	if v := ratio(2, 3); *v != 0.667 {
		t.Fatalf("ratio(2, 3) = %v, want 0.667", *v)
	}
}

// An empty corpus scores every tier with no run and no class, and its
// page renders with empty tables instead of dividing by zero.
func TestScoreEmptyCorpus(t *testing.T) {
	tiers, err := Score(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tiers) != len(Tiers()) {
		t.Fatalf("tiers %+v", tiers)
	}
	for _, tr := range tiers {
		if tr.Runs != 0 || tr.IncompleteRuns != 0 || len(tr.Classes) != 0 {
			t.Errorf("tier %+v", tr)
		}
	}
	if md := (Results{Tiers: tiers}).Markdown(); strings.Contains(md, "NaN") || strings.Contains(md, "Inf") {
		t.Errorf("markdown %q", md)
	}
	if _, err := Score(nil, []Outcome{{Tier: "S", Case: "a", Variant: Safe}}); err == nil {
		t.Error("an outcome for a case not in an empty corpus was scored")
	}
}

func TestScoreRefusesBadOutcomes(t *testing.T) {
	tests := []struct {
		name     string
		outcomes []Outcome
		want     string
	}{
		{"missing run", allRuns(func(*Outcome) {})[1:], "runs"},
		{"run twice", append(allRuns(func(*Outcome) {}), Outcome{Tier: "S", Case: "a", Variant: Safe}), "twice"},
		{"unknown case", append(allRuns(func(*Outcome) {}), Outcome{Tier: "S", Case: "z", Variant: Safe}), "unknown case"},
		{"unknown tier", append(allRuns(func(*Outcome) {}), Outcome{Tier: "XL", Case: "a", Variant: Safe}), "tier"},
		{"unknown variant", append(allRuns(func(*Outcome) {}), Outcome{Tier: "S", Case: "a", Variant: "fixed"}), "variant"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Score(scoreCases(), tc.outcomes)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
}
