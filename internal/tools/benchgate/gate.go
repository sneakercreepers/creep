package main

import (
	"errors"
	"fmt"

	"github.com/sneakercreepers/creep/internal/bench"
)

// slack absorbs float rounding, so a drop of exactly the threshold passes.
const slack = 1e-9

// tierTotals are one tier's counts summed over its classes. The gate
// compares tiers, not classes: with one or two cases a class swings by 0.5
// on a single reply, a tier by about 0.08.
type tierTotals struct {
	vulnerable, detected, safe, falsePositives, claimed, silent int
}

func sumTier(t bench.TierResult) tierTotals {
	var s tierTotals
	for _, c := range t.Classes {
		s.vulnerable += c.Vulnerable
		s.detected += c.Detected
		s.safe += c.Safe
		s.falsePositives += c.FalsePositives
		s.claimed += c.ClaimedCovered
		s.silent += c.SilentMisses
	}
	return s
}

// metric is one rate of a tier, in the baseline and in the new results.
// worseUp is true when a higher value is worse (the false-positive rate).
type metric struct {
	name      string
	base, got *float64
	worseUp   bool
}

func metrics(base, got tierTotals) []metric {
	return []metric{
		{"recall", rate(base.detected, base.vulnerable), rate(got.detected, got.vulnerable), false},
		{"false-positive rate", rate(base.falsePositives, base.safe), rate(got.falsePositives, got.safe), true},
		{"honesty", rate(base.claimed-base.silent, base.claimed), rate(got.claimed-got.silent, got.claimed), false},
	}
}

// rate is n/d, or nil when d is 0: a rate over nothing is unmeasured.
func rate(n, d int) *float64 {
	if d == 0 {
		return nil
	}
	v := float64(n) / float64(d)
	return &v
}

// check reports why m regressed by more than maxDrop, or "" when it did
// not. A rate the baseline measured and the results did not is a
// regression: nothing measured must never pass as nothing lost.
func (m metric) check(maxDrop float64) string {
	if m.base == nil {
		return ""
	}
	if m.got == nil {
		return fmt.Sprintf("%s was %.3f and is now unmeasured", m.name, *m.base)
	}
	drop := *m.base - *m.got
	if m.worseUp {
		drop = -drop
	}
	if drop <= maxDrop+slack {
		return ""
	}
	return fmt.Sprintf("%s %.3f, baseline %.3f: worse by %.3f, over the %.3f threshold", m.name, *m.got, *m.base, drop, maxDrop)
}

// errSynthesized refuses results no model answered: the gate measures a
// live model, and synthesized numbers would compare an oracle.
var errSynthesized = errors.New("synthesized results: the gate compares live runs only")

// compare returns the regressions of got against base. A baseline without
// tiers is not set yet and passes; one measured on another corpus or model
// cannot be compared, so it fails until the baseline is set again.
func compare(base, got bench.Results, maxDrop float64) ([]string, error) {
	for _, r := range []bench.Results{base, got} {
		if r.SchemaVersion != bench.SchemaVersion {
			return nil, fmt.Errorf("schema_version %d, want %d", r.SchemaVersion, bench.SchemaVersion)
		}
		if r.Model.Synthesized {
			return nil, errSynthesized
		}
	}
	if len(base.Tiers) == 0 {
		return nil, nil
	}
	if problems := mismatch(base, got); len(problems) > 0 {
		return problems, nil
	}
	return tierProblems(base, got, maxDrop), nil
}

func tierProblems(base, got bench.Results, maxDrop float64) []string {
	var problems []string
	for _, bt := range base.Tiers {
		gt, ok := findTier(got, bt.Tier)
		if !ok {
			problems = append(problems, fmt.Sprintf("tier %s: in the baseline, missing from the results", bt.Tier))
			continue
		}
		for _, m := range metrics(sumTier(bt), sumTier(gt)) {
			if why := m.check(maxDrop); why != "" {
				problems = append(problems, fmt.Sprintf("tier %s: %s", bt.Tier, why))
			}
		}
	}
	return problems
}

func mismatch(base, got bench.Results) []string {
	var problems []string
	if base.Corpus.SHA256 != got.Corpus.SHA256 {
		problems = append(problems, fmt.Sprintf("corpus %q, baseline measured %q: set the baseline again", got.Corpus.SHA256, base.Corpus.SHA256))
	}
	if base.Model.Contract != got.Model.Contract || base.Model.Name != got.Model.Name {
		problems = append(problems, fmt.Sprintf("model %s %q, baseline measured %s %q: set the baseline again",
			got.Model.Contract, got.Model.Name, base.Model.Contract, base.Model.Name))
	}
	return problems
}

func findTier(r bench.Results, tier string) (bench.TierResult, bool) {
	for _, t := range r.Tiers {
		if t.Tier == tier {
			return t, true
		}
	}
	return bench.TierResult{}, false
}
