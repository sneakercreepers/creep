package report

import "fmt"

// MaxStabilityRuns mirrors discover.MaxSamples, the most samples a
// --stability run takes; report may not import discover (layer table), so
// a CLI test keeps both equal.
const MaxStabilityRuns = 5

// Stability is how many of a --stability run's samples saw a finding:
// Seen of Runs (ADR 0024). A sample saw it when its discovery named the
// sink and its reader answered vulnerable. It is about the model, not the
// code: a finding seen in fewer than Runs samples is an unstable
// discovery, which is not an intermittent PoC (PoCRate, ADR 0020), where
// the app itself answered differently.
type Stability struct {
	Runs int `json:"runs"`
	Seen int `json:"seen"`
	// Unstable is Seen < Runs, stated so a JSON consumer need not derive it.
	Unstable bool `json:"unstable"`
}

// NewStability is the stability of a finding seen in seen of runs samples.
func NewStability(seen, runs int) *Stability {
	return &Stability{Runs: runs, Seen: seen, Unstable: seen < runs}
}

// Text is "unstable discovery: seen in 2 of 3 runs", "stable discovery:
// seen in 3 of 3 runs", or "" with no stability run.
func (s *Stability) Text() string {
	if s == nil {
		return ""
	}
	word := "stable"
	if s.Unstable {
		word = "unstable"
	}
	return fmt.Sprintf("%s discovery: seen in %d of %d runs", word, s.Seen, s.Runs)
}

// checkStability refuses a count no stability run makes, a label that
// does not match it, and stability on a finding that is not probable or
// verified: only a finding is labeled, never a candidate the run
// discarded or could not evaluate.
func checkStability(f Finding) error {
	s := f.Stability
	if s == nil {
		return nil
	}
	finding := f.Status == StatusProbable || f.Status == StatusVerified
	if !finding || s.Runs < 2 || s.Runs > MaxStabilityRuns || s.Seen < 0 || s.Seen > s.Runs || s.Unstable != (s.Seen < s.Runs) {
		return fmt.Errorf("%w: finding %s: %s with stability %+v", ErrInvalid, f.ID, f.Status, *s)
	}
	return nil
}
