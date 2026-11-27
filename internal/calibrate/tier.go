package calibrate

import (
	"math/big"
	"slices"
)

// Tier is how much creep trusts a model, from the calibration result. The
// planner bounds its strategy by it (#12).
type Tier string

const (
	TierS Tier = "S" // small: bounded steps; the default when anything is unmeasured
	TierM Tier = "M"
	TierL Tier = "L"
)

// maxInvalidPercent is the share of task replies that may fail to decode
// before the structured-output check fails. Exactly this share passes.
const maxInvalidPercent = 5

// tierRule is what a model needs for one tier. Every bound is inclusive,
// and score bounds apply to the Wilson lower bound, not the point score,
// so a class with few tasks cannot earn a tier by luck.
type tierRule struct {
	tier         Tier
	tools        bool     // the tool-calling check must pass
	contextBytes int      // minimum effective context
	overallLower *big.Rat // minimum lower bound over all tasks
	classLower   *big.Rat // minimum lower bound of every class
}

// tierRules go from the highest tier down; the first one met wins.
//
// Both bounds read only the PlannedClasses (#363): the overall one is over
// their tasks, 64 of the 100 for every seed. With 14 tasks a class needs
// 11 right for L (lower 0.524) and 7 for M (0.268); with 8 tasks, 7
// (0.529) and 5 (0.306). Over the 64 planned tasks L needs 55 right and M
// 44. A model that answers "safe" to everything gets 32 (and 4 of 8 in
// the smaller classes, lower 0.215), so it stays S, and the fitness floor
// (fitness.go) refuses it.
func tierRules() []tierRule {
	return []tierRule{
		{tier: TierL, tools: true, contextBytes: 128 << 10, overallLower: big.NewRat(3, 4), classLower: big.NewRat(1, 2)},
		{tier: TierM, tools: false, contextBytes: 32 << 10, overallLower: big.NewRat(11, 20), classLower: big.NewRat(1, 4)},
	}
}

// StructuredCheck counts task replies that never decoded into a valid
// answer, retries included.
type StructuredCheck struct {
	Total   int  `json:"total"`
	Invalid int  `json:"invalid"`
	Passed  bool `json:"passed"`
}

func newStructuredCheck(total, invalid int) StructuredCheck {
	passed := total > 0 && invalid*100 <= total*maxInvalidPercent
	return StructuredCheck{Total: total, Invalid: invalid, Passed: passed}
}

// ToolCheck counts tool-calling probes answered with the right tool and
// the exact argument. It passes only when every probe does.
type ToolCheck struct {
	Probes  int  `json:"probes"`
	Correct int  `json:"correct"`
	Passed  bool `json:"passed"`
}

func newToolCheck(probes, correct int) ToolCheck {
	return ToolCheck{Probes: probes, Correct: correct, Passed: probes > 0 && correct == probes}
}

// ContextCheck is the largest probe size, in bytes, the model answered,
// with every smaller size answered too; 0 when it failed the first. When a
// probe failed it also records which size and why (#174): a refusal for a
// reason other than size (a 400 for a bad parameter, say) under-rates the
// model, and the report must show that instead of hiding it in a low tier.
type ContextCheck struct {
	EffectiveBytes int `json:"effective_bytes"`
	// StoppedAt is the size of the probe that failed; 0 when every size was
	// answered.
	StoppedAt int         `json:"stopped_at,omitempty"`
	Stop      ContextStop `json:"stop,omitempty"`
	// Status is the HTTP status of the refusal when Stop is ContextStopStatus.
	Status int `json:"status,omitempty"`
}

// ContextStop is why the effective-context probe stopped.
type ContextStop string

// The reasons a context probe fails without ending the run.
const (
	ContextStopWrongAnswer   ContextStop = "wrong_answer"
	ContextStopInvalidOutput ContextStop = "invalid_output"
	ContextStopStatus        ContextStop = "status" // HTTP 400 or 413
	ContextStopBudget        ContextStop = "budget" // the token budget refused the call
)

// consistent reports whether c could have come from runContextProbes: a
// stop names the next size after the effective one, and only a status
// stop carries a status. A cached result that is not is never trusted.
func (c ContextCheck) consistent() bool {
	i := slices.Index(contextSizes, c.EffectiveBytes)
	if c.EffectiveBytes != 0 && i < 0 {
		return false
	}
	if c.Stop == "" {
		return c.StoppedAt == 0 && c.Status == 0 && c.EffectiveBytes == contextSizes[len(contextSizes)-1]
	}
	if i+1 >= len(contextSizes) || c.StoppedAt != contextSizes[i+1] {
		return false
	}
	switch c.Stop {
	case ContextStopStatus:
		return c.Status == 400 || c.Status == 413
	case ContextStopWrongAnswer, ContextStopInvalidOutput, ContextStopBudget:
		return c.Status == 0
	}
	return false
}

// Tiers lists every tier assignTier can return (the default and one per
// rule), so a package that maps tiers can test that it covers each one.
func Tiers() []Tier {
	tiers := []Tier{TierS}
	for _, rule := range tierRules() {
		tiers = append(tiers, rule.tier)
	}
	return tiers
}

// assignTier returns the highest tier whose rule r meets, or TierS. It
// reads only counts and integers, so a recorded run always gets the same
// tier on every platform.
func assignTier(r Result) Tier {
	for _, rule := range tierRules() {
		if meets(r, rule) {
			return rule.tier
		}
	}
	return TierS
}

func meets(r Result, rule tierRule) bool {
	if !r.Structured.Passed || (rule.tools && !r.Tools.Passed) {
		return false
	}
	if r.Context.EffectiveBytes < rule.contextBytes {
		return false
	}
	planned, ok := plannedScores(r)
	if !ok {
		return false
	}
	overall := sumScores(planned)
	if !lowerAtLeast(overall.Correct, overall.Total, rule.overallLower) {
		return false
	}
	for _, c := range planned {
		if !lowerAtLeast(c.Correct, c.Total, rule.classLower) {
			return false
		}
	}
	return true
}

// plannedScores returns the scores of the PlannedClasses, in their order,
// and false unless r scores every calibrated class exactly once: a result
// that leaves a class out is unmeasured and keeps the model at tier S.
func plannedScores(r Result) ([]ClassScore, bool) {
	if len(r.Classes) != len(Classes()) {
		return nil, false
	}
	byClass := make(map[Class]ClassScore, len(r.Classes))
	for _, c := range r.Classes {
		byClass[c.Class] = c
	}
	out := make([]ClassScore, 0, len(PlannedClasses()))
	for _, c := range Classes() {
		s, ok := byClass[c]
		if !ok {
			return nil, false
		}
		if slices.Contains(PlannedClasses(), c) {
			out = append(out, s)
		}
	}
	return out, true
}

// sumScores adds up the counts of scores into one ClassScore.
func sumScores(scores []ClassScore) ClassScore {
	var sum ClassScore
	for _, s := range scores {
		sum.Correct += s.Correct
		sum.Total += s.Total
		sum.SafeTwins += s.SafeTwins
		sum.SafeFlagged += s.SafeFlagged
	}
	sum.Score = newScore(sum.Correct, sum.Total)
	return sum
}
