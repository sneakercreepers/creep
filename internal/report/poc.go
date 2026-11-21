package report

import "fmt"

// maxPoCRuns mirrors verify.MaxRuns, which report may not import (layer
// table); a CLI test keeps both equal.
const maxPoCRuns = 20

// PoCRate is how many runs of a finding's PoC verified it: Verified of
// Runs. The zero value means no PoC verified the finding.
type PoCRate struct {
	Verified int
	Runs     int
}

// Intermittent is a PoC that verified in some runs and not in others.
func (r PoCRate) Intermittent() bool { return r.Verified > 0 && r.Verified < r.Runs }

// Text is "verified in 3/5 runs, intermittent", or "" without a PoC.
func (r PoCRate) Text() string {
	if r.Runs == 0 {
		return ""
	}
	text := fmt.Sprintf("verified in %d/%d runs", r.Verified, r.Runs)
	if r.Intermittent() {
		text += ", intermittent"
	}
	return text
}

// checkPoC refuses a rate no repetition makes, and a rate on a finding
// that is not verified: no finding is verified from 0 runs, and a
// discarded PoC leaves no rate.
func checkPoC(f Finding) error {
	r := f.PoC
	if r == (PoCRate{}) {
		return nil
	}
	if f.Status != StatusVerified || r.Verified < 1 || r.Verified > r.Runs || r.Runs > maxPoCRuns {
		return fmt.Errorf("%w: finding %s: %s with a PoC verified in %d of %d runs", ErrInvalid, f.ID, f.Status, r.Verified, r.Runs)
	}
	return nil
}
