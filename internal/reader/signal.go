package reader

import (
	"errors"
	"fmt"
)

// HypothesisID names the planner's hypothesis a verdict answers. The
// planner assigns it; reader only echoes it back.
type HypothesisID uint32

// Verdict is the planner-facing verdict. The zero value is not a verdict,
// so a Signal that was never filled in is never read as one.
type Verdict uint8

const (
	VerdictInconclusive Verdict = iota + 1
	VerdictNotVulnerable
	VerdictVulnerable
)

// LineRange is an inclusive range of file line numbers.
type LineRange struct {
	Start uint32
	End   uint32
}

// Signal is the only reader output the planner may receive. It holds IDs,
// enums and numbers and nothing that can carry text (invariant 3);
// signal_test.go fails the build if that changes. The caller copies it
// into the planner's own type, since planner may not import reader.
type Signal struct {
	Hypothesis HypothesisID
	Verdict    Verdict
	Confidence uint8 // 0-100
	Evidence   []LineRange
	// Partial is Slice.Partial: the verdict was reached on a slice that
	// left lines out, so it is partial coverage, never a clean result.
	Partial bool
}

// ErrEvidence means an answer cites a line the model was not shown.
var ErrEvidence = errors.New("reader: evidence outside the lines shown")

// Project turns a validated answer about hypothesis h into a Signal. shown
// lists the line ranges the user turn contained; every evidence range must
// lie inside one of them. a must have passed Validate, which models.Complete
// runs; Project checks it again so a caller cannot skip it.
func Project(h HypothesisID, a Answer, shown []LineRange) (Signal, error) {
	if err := a.Validate(); err != nil {
		return Signal{}, fmt.Errorf("reader: %w", err)
	}
	evidence := make([]LineRange, 0, len(a.Evidence))
	for _, e := range a.Evidence {
		r := LineRange{Start: uint32(e.Start), End: uint32(e.End)} //nolint:gosec // G115: Validate bounds both to 1..MaxLine
		if !within(r, shown) {
			return Signal{}, ErrEvidence
		}
		evidence = append(evidence, r)
	}
	return Signal{
		Hypothesis: h,
		Verdict:    verdictOf(a.Verdict),
		Confidence: uint8(*a.Confidence), //nolint:gosec // G115: Validate bounds it to 0..100
		Evidence:   evidence,
	}, nil
}

func within(r LineRange, shown []LineRange) bool {
	for _, s := range shown {
		if s.Start <= r.Start && r.End <= s.End {
			return true
		}
	}
	return false
}

// verdictOf maps a validated verdict string to its enum.
func verdictOf(s string) Verdict {
	switch s {
	case answerVulnerable:
		return VerdictVulnerable
	case answerNotVulnerable:
		return VerdictNotVulnerable
	}
	return VerdictInconclusive
}
