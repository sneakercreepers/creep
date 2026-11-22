package verify

import (
	"context"
	"fmt"
)

// DefaultRuns is how many times a scan runs each PoC (#25): enough to
// tell a stable flaw from an intermittent one, such as a race.
const DefaultRuns = 5

// MaxRuns bounds the runs of one PoC, so a bundle stays small and a
// repetition ends.
const MaxRuns = 20

// Rate is how many runs of a PoC its oracle held in.
type Rate struct {
	Verified int `json:"verified"`
	Runs     int `json:"runs"`
}

// Valid is a rate a repetition can produce: 1 to MaxRuns runs, and no
// more verified runs than runs.
func (r Rate) Valid() bool {
	return r.Runs >= 1 && r.Runs <= MaxRuns && r.Verified >= 0 && r.Verified <= r.Runs
}

// Holds is true when at least one run verified. A PoC whose every run
// failed (0 of N) proves nothing: its finding keeps the reader's status.
func (r Rate) Holds() bool { return r.Valid() && r.Verified > 0 }

// Intermittent is true when some runs verified and some did not: a flaw
// that depends on timing or state, reported verified with its rate.
func (r Rate) Intermittent() bool { return r.Holds() && r.Verified < r.Runs }

// String is "3/5".
func (r Rate) String() string { return fmt.Sprintf("%d/%d", r.Verified, r.Runs) }

// Repetition is every run of one PoC, in order, and its rate.
type Repetition struct {
	Rate    Rate
	Results []Result
}

// Repeat runs p runs times against t through r. Each run has its own fresh
// nonce (Run), so a marker table or a stored probe from one run never
// verifies another. A sandbox error ends the repetition and is returned:
// no rate is made of the runs before it.
func Repeat(ctx context.Context, r Runner, t Target, p PoC, runs int) (Repetition, error) {
	if runs < 1 || runs > MaxRuns {
		return Repetition{}, fmt.Errorf("repeat: %d runs, want 1 to %d: %w", runs, MaxRuns, ErrInvalid)
	}
	rep := Repetition{Rate: Rate{Runs: runs}, Results: make([]Result, 0, runs)}
	for range runs {
		res, err := Run(ctx, r, t, p)
		if err != nil {
			return Repetition{}, fmt.Errorf("repeat: run %d of %d: %w", len(rep.Results)+1, runs, err)
		}
		if res.Outcome == Verified {
			rep.Rate.Verified++
		}
		rep.Results = append(rep.Results, res)
	}
	return rep, nil
}
