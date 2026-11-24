package bench

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
)

// lineSlack is how far a finding may sit from the planted sink and still
// count: the source line may be just above it, as in calibration scoring.
const lineSlack = 2

// Tiers are the model tiers the bench runs, in order.
func Tiers() []string { return []string{"S", "M", "L"} }

// Finding is what scoring needs of one scan finding: its class, its line
// and whether the scan flagged it (probable or verified).
type Finding struct {
	Class   string
	Line    int
	Flagged bool
}

// Outcome is one case twin scanned at one tier.
type Outcome struct {
	Tier     string
	Case     string
	Variant  Variant
	Findings []Finding
	// Covered is true when the run reported the case's class covered: a
	// claim that nothing of that class was left unchecked.
	Covered bool
	// Incomplete is true when the run would have exited 4.
	Incomplete bool
}

// ClassResult is one class at one tier.
type ClassResult struct {
	Class string `json:"class"`
	// Vulnerable twins run, and those whose planted sink a flagged finding
	// of the class hit (within lineSlack lines).
	Vulnerable int      `json:"vulnerable"`
	Detected   int      `json:"detected"`
	Recall     *float64 `json:"recall"`
	// Safe twins run, and those with any flagged finding, of any class.
	Safe              int      `json:"safe"`
	FalsePositives    int      `json:"false_positives"`
	FalsePositiveRate *float64 `json:"false_positive_rate"`
	// Vulnerable twins whose run claimed the class covered, those claims
	// that missed the planted sink, and the share of claims that held.
	ClaimedCovered int      `json:"claimed_covered"`
	SilentMisses   int      `json:"silent_misses"`
	Honesty        *float64 `json:"honesty"`
}

// TierResult is every class at one tier.
type TierResult struct {
	Tier           string        `json:"tier"`
	Runs           int           `json:"runs"`
	IncompleteRuns int           `json:"incomplete_runs"`
	Classes        []ClassResult `json:"classes"`
}

// Score turns outcomes into per-tier, per-class results. Every case must
// have both twins at every tier, exactly once.
func Score(cases []Case, outcomes []Outcome) ([]TierResult, error) {
	byID := map[string]Case{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	if err := checkOutcomes(byID, outcomes); err != nil {
		return nil, err
	}
	var out []TierResult
	for _, tier := range Tiers() {
		out = append(out, scoreTier(tier, byID, outcomes))
	}
	return out, nil
}

func checkOutcomes(byID map[string]Case, outcomes []Outcome) error {
	seen := map[[3]string]bool{}
	for _, o := range outcomes {
		key := [3]string{o.Tier, o.Case, string(o.Variant)}
		switch {
		case !slices.Contains(Tiers(), o.Tier) || !slices.Contains(Variants(), o.Variant):
			return errors.New("bench outcome: unknown tier or variant")
		case byID[o.Case].ID == "":
			return fmt.Errorf("bench outcome: unknown case %q", o.Case)
		case seen[key]:
			return fmt.Errorf("bench outcome: %s %s %s scored twice", o.Tier, o.Case, o.Variant)
		}
		seen[key] = true
	}
	if want := len(Tiers()) * len(byID) * len(Variants()); len(seen) != want {
		return fmt.Errorf("bench outcome: %d runs, want %d", len(seen), want)
	}
	return nil
}

func scoreTier(tier string, byID map[string]Case, outcomes []Outcome) TierResult {
	t := TierResult{Tier: tier}
	rows := map[string]*ClassResult{}
	for _, o := range outcomes {
		if o.Tier != tier {
			continue
		}
		c := byID[o.Case]
		row := rows[c.Class]
		if row == nil {
			row = &ClassResult{Class: c.Class}
			rows[c.Class] = row
		}
		t.Runs++
		if o.Incomplete {
			t.IncompleteRuns++
		}
		row.add(c, o)
	}
	for _, name := range slices.Sorted(maps.Keys(rows)) {
		t.Classes = append(t.Classes, rows[name].withRates())
	}
	return t
}

func (r *ClassResult) add(c Case, o Outcome) {
	if o.Variant == Safe {
		r.Safe++
		if slices.ContainsFunc(o.Findings, func(f Finding) bool { return f.Flagged }) {
			r.FalsePositives++
		}
		return
	}
	r.Vulnerable++
	hit := detects(o.Findings, c.Class, c.Twin(Vulnerable).Sink)
	if hit {
		r.Detected++
	}
	if o.Covered {
		r.ClaimedCovered++
		if !hit {
			r.SilentMisses++
		}
	}
}

// detects reports a flagged finding of class on the sink line, or within
// lineSlack lines of it.
func detects(findings []Finding, class string, sink int) bool {
	return slices.ContainsFunc(findings, func(f Finding) bool {
		return f.Flagged && f.Class == class && f.Line >= sink-lineSlack && f.Line <= sink+lineSlack
	})
}

func (r ClassResult) withRates() ClassResult {
	r.Recall = ratio(r.Detected, r.Vulnerable)
	r.FalsePositiveRate = ratio(r.FalsePositives, r.Safe)
	r.Honesty = ratio(r.ClaimedCovered-r.SilentMisses, r.ClaimedCovered)
	return r
}

// ratio is n/d rounded to three decimals, or nil when d is 0: a rate over
// nothing is unmeasured, not 0 or 1.
func ratio(n, d int) *float64 {
	if d == 0 {
		return nil
	}
	v := math.Round(float64(n)/float64(d)*1000) / 1000
	return &v
}
