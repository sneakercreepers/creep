package main

import (
	"errors"
	"fmt"

	"github.com/sneakercreepers/creep/internal/bench"
)

// slack absorbs float rounding, so a drop of exactly the threshold passes.
const slack = 1e-9

// metric is one rate of a tier, in the baseline and in the new results.
// worseUp is true when a higher value is worse (the false-positive rate).
type metric struct {
	name      string
	base, got *float64
	worseUp   bool
}

// metrics compares tiers, not classes: with one or two cases a class
// swings by 0.5 on a single reply, a tier by about 0.08. The rates come
// from bench.TierResult.Totals, the bench's own definition, rounded to
// three decimals as published; a nil rate is unmeasured.
func metrics(base, got bench.TierResult) []metric {
	b, g := base.Totals(), got.Totals()
	return []metric{
		{"recall", b.Recall, g.Recall, false},
		{"false-positive rate", b.FalsePositiveRate, g.FalsePositiveRate, true},
		{"honesty", b.Honesty, g.Honesty, false},
	}
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
		if mostlyIncomplete(bt) || mostlyIncomplete(gt) {
			continue // reported by noisyTiers, never a regression
		}
		for _, m := range metrics(bt, gt) {
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

// mostlyIncomplete reports a tier where more than half the case runs did
// not finish (a reply broke the schema, say): its counts rest on the few
// runs that did, so one reply swings them past any threshold (v0.3
// tester T3). Such a tier is not compared, on either side.
func mostlyIncomplete(t bench.TierResult) bool {
	return t.IncompleteRuns*2 > t.Runs
}

// noisyTiers names each tier the gate did not compare because the
// baseline or the results ran it mostly incomplete.
func noisyTiers(base, got bench.Results) []string {
	if len(base.Tiers) == 0 {
		return nil
	}
	var notes []string
	for _, bt := range base.Tiers {
		gt, ok := findTier(got, bt.Tier)
		if !ok || (!mostlyIncomplete(bt) && !mostlyIncomplete(gt)) {
			continue
		}
		notes = append(notes, fmt.Sprintf("tier %s not compared: incomplete runs %d of %d in the baseline, %d of %d in the results (more than half on a side is noise)",
			bt.Tier, bt.IncompleteRuns, bt.Runs, gt.IncompleteRuns, gt.Runs))
	}
	return notes
}
