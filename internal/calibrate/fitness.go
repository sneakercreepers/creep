package calibrate

import (
	"errors"
	"fmt"
	"math/big"
)

// ErrUnfit is wrapped by UnfitError: the calibration says the model cannot
// tell a vulnerable sink from its safe twin, so a scan refuses it unless
// the user overrides (ADR 0036).
var ErrUnfit = errors.New("model unfit")

// UnfitReason says which floor an unfit model missed.
type UnfitReason string

// The fitness floors, checked in this order.
const (
	// UnfitBelowChance: the planned classes' score is not above chance.
	UnfitBelowChance UnfitReason = "below_chance"
	// UnfitFlagsSafeTwins: the model did not call most safe twins safe.
	UnfitFlagsSafeTwins UnfitReason = "flags_safe_twins"
)

// chance is the score of a model that ignores the code: Generate makes half
// the tasks vulnerable and half their safe twins, in every class, so
// answering always "vulnerable", always "safe" or by coin flip scores 1/2.
// The floor reads the Wilson lower bound, like the tier rules, so a model
// is fit only when its score is above chance at 95% confidence: with the
// 64 planned tasks of every seed it needs 40 right (lower 0.503).
func chance() *big.Rat { return big.NewRat(1, 2) }

// Fitness is the fitness floor's verdict on a Result, over the
// PlannedClasses only. It is stored with the Result, so a cached unfit
// model is refused without a new calibration.
type Fitness struct {
	Fit    bool        `json:"fit"`
	Reason UnfitReason `json:"reason,omitempty"`
	// Planned is the score over the planned classes' tasks, with how many
	// of them were safe twins and how many the model did not call safe.
	Planned ClassScore `json:"planned"`
}

// assessFitness applies the two floors (ADR 0036). The safe-twin floor is a
// plain majority, not an interval: "flags most safe twins" is a count, and
// the score floor already demands confidence. A model that answers
// "vulnerable" to every task passes neither: half its planned answers are
// wrong and it flags every twin. A result missing a class is unfit.
func assessFitness(r Result) Fitness {
	planned, ok := plannedScores(r)
	if !ok {
		return Fitness{Reason: UnfitBelowChance}
	}
	f := Fitness{Planned: sumScores(planned)}
	f.Planned.Class = ""
	switch {
	case !lowerAtLeast(f.Planned.Correct, f.Planned.Total, chance()):
		f.Reason = UnfitBelowChance
	case f.Planned.SafeTwins == 0 || 2*f.Planned.SafeFlagged > f.Planned.SafeTwins:
		f.Reason = UnfitFlagsSafeTwins
	default:
		f.Fit = true
	}
	return f
}

// sameVerdict compares the verdict and the counts behind it, not the
// display interval, so a cached verdict never hinges on float output.
func (f Fitness) sameVerdict(g Fitness) bool {
	a, b := f.Planned, g.Planned
	return f.Fit == g.Fit && f.Reason == g.Reason && a.Class == b.Class &&
		a.Correct == b.Correct && a.Total == b.Total && a.SafeTwins == b.SafeTwins && a.SafeFlagged == b.SafeFlagged
}

// UnfitError is the refusal of an unfit model, with the measured numbers.
type UnfitError struct {
	Fitness Fitness
}

func (e *UnfitError) Error() string {
	p := e.Fitness.Planned
	return fmt.Sprintf("%s (%s): %d of %d tasks in the planned classes right (95%% lower bound %.3f, needs at least 0.5, chance); "+
		"%d of %d safe twins not called safe (needs at most half); pass --allow-unfit-model to scan anyway, every finding labeled unreliable_model",
		ErrUnfit, e.Fitness.Reason, p.Correct, p.Total, p.Lower, p.SafeFlagged, p.SafeTwins)
}

func (e *UnfitError) Unwrap() error { return ErrUnfit }

// CheckFit returns an *UnfitError when the calibration is unfit, else nil.
func (c Calibration) CheckFit() error {
	if c.Fitness.Fit {
		return nil
	}
	return &UnfitError{Fitness: c.Fitness}
}

// fitnessNote is the Header's mark of a model scanned past the floor.
func fitnessNote(f Fitness) string {
	if f.Fit {
		return ""
	}
	return fmt.Sprintf(" · UNFIT (%s, %d/%d planned tasks, %d/%d safe twins flagged): findings labeled unreliable_model",
		f.Reason, f.Planned.Correct, f.Planned.Total, f.Planned.SafeFlagged, f.Planned.SafeTwins)
}
