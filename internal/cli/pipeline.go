package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/planner"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/report"
)

// Finding reasons the scan adds to the report's own (ADR 0009). All are IDs.
const (
	reasonLowRisk         = "low_risk"
	reasonStepCap         = "step_cap"
	reasonPlanBudget      = "budget"
	reasonPlannerRejected = "planner_rejected"
	reasonUnmappedKind    = "unmapped_kind"
	reasonUnmappedClass   = "unmapped_class"
	reasonInconclusive    = "inconclusive"
	reasonInvalidOutput   = "invalid_output"
	reasonNotEvaluated    = "not_evaluated"
	reasonPartialSlice    = "partial_slice"
)

// baseFindings has one finding per sink, at the sink's index (discover
// numbers sinks 1..n), each not evaluated until a stage decides it: a sink
// no stage reaches stays listed.
func baseFindings(rs repoScan) []report.Finding {
	out := make([]report.Finding, len(rs.res.Sinks))
	for i, s := range rs.res.Sinks {
		out[i] = report.Finding{
			ID: fmt.Sprintf("sink-%d", s.ID), Class: kindClass(s.Kind), Status: report.StatusNotEvaluated,
			Path: rs.paths[s.File], Line: int(s.Line),
		}
	}
	return out
}

// sinkIndex is the finding index of a planner or discover sink ID.
func sinkIndex[ID ~uint32](id ID) int { return int(id) - 1 }

// planSinks builds the plan and records every sink it leaves out, with its
// reason. planner.ErrInput is returned for the caller to fail closed.
func planSinks(rs repoScan, tier planner.Tier, budget planner.Budget, findings []report.Finding) (planner.Plan, error) {
	in, unmapped := plannerInput(rs.res, tier, budget)
	for _, id := range unmapped {
		findings[sinkIndex(id)].Reason = reasonUnmappedKind
	}
	plan, err := planner.Build(in)
	if err != nil {
		return planner.Plan{}, err
	}
	for _, s := range plan.Skipped {
		findings[sinkIndex(s.Sink)].Reason = skipName(s.Reason)
	}
	return plan, nil
}

func skipName(r planner.SkipReason) string {
	switch r {
	case planner.SkipLowRisk:
		return reasonLowRisk
	case planner.SkipStepCap:
		return reasonStepCap
	case planner.SkipBudget:
		return reasonPlanBudget
	}
	return reasonNotEvaluated // unknown: a gap, never a by-design skip
}

// readStage evaluates the plan's hypotheses with the reader.
type readStage struct {
	model  *models.HTTP
	tier   reader.Tier
	slicer reader.Slicer
}

// run slices and evaluates every hypothesis. It returns the files the
// slicer could not use and the reason the run stopped early, if it did.
func (r readStage) run(ctx context.Context, plan planner.Plan, rs repoScan, findings []report.Finding) ([]report.NotEvaluated, string, error) {
	targets, sinkOf := targetsFor(plan, rs, findings)
	rep, err := r.slicer.Build(targets)
	if err != nil && !rep.Incomplete {
		return nil, "", err
	}
	gaps, incomplete := notEvaluatedFrom(gateway.ScanReport{NotScanned: rep.NotScanned, Incomplete: rep.Incomplete})
	for _, n := range rep.NotEvaluated {
		findings[sinkOf[n.Hypothesis]].Reason = string(n.Reason)
	}
	stop := r.evaluate(ctx, rep.Slices, sinkOf, findings)
	if incomplete {
		stop = string(report.SkipRunFull)
	}
	return gaps, stop, nil
}

// targetsFor turns hypotheses into reader targets. The route's first line
// is the source (line 1 for a file-level route) and the sink's line the
// sink; the path comes from the walk, by the sink's file ID. sinkOf maps a
// hypothesis to its finding index.
func targetsFor(plan planner.Plan, rs repoScan, findings []report.Finding) ([]reader.Target, map[reader.HypothesisID]int) {
	targets := make([]reader.Target, 0, len(plan.Hypotheses))
	sinkOf := make(map[reader.HypothesisID]int, len(plan.Hypotheses))
	for _, h := range plan.Hypotheses {
		at := sinkIndex(h.Sink)
		class, err := readerClass(h.Class)
		if err != nil {
			findings[at].Reason = reasonUnmappedClass
			continue
		}
		sink, route := rs.res.Sinks[at], rs.res.Routes[sinkIndex(h.Route)]
		id := reader.HypothesisID(h.ID)
		targets = append(targets, reader.Target{
			Hypothesis: id, Class: class, Path: rs.paths[sink.File],
			SourceLine: int(route.Lines.Start), SinkLine: int(sink.Line),
		})
		sinkOf[id] = at
	}
	return targets, sinkOf
}

// evaluate asks the model about each slice in plan order. A failure that
// ends the run (budget, run_full, transport) marks this and every later
// hypothesis with its reason and returns it; a bad answer marks only its
// own hypothesis.
func (r readStage) evaluate(ctx context.Context, slices []reader.Slice, sinkOf map[reader.HypothesisID]int, findings []report.Finding) string {
	for i, s := range slices {
		f := &findings[sinkOf[s.Hypothesis]]
		sig, err := reader.Evaluate(ctx, r.model, r.tier, s)
		if err == nil {
			applySignal(f, sig)
			continue
		}
		reason, stop := evalFailure(err)
		f.Reason = reason
		if !stop {
			continue
		}
		for _, rest := range slices[i+1:] {
			findings[sinkOf[rest.Hypothesis]].Reason = reason
		}
		return reason
	}
	return ""
}

func applySignal(f *report.Finding, sig reader.Signal) {
	switch sig.Verdict {
	case reader.VerdictVulnerable:
		f.Status = report.StatusProbable
	case reader.VerdictNotVulnerable:
		f.Status = report.StatusDiscarded
	default:
		f.Reason = reasonInconclusive
	}
	f.Confidence, f.Partial = int(sig.Confidence), sig.Partial
	for _, e := range sig.Evidence {
		f.Evidence = append(f.Evidence, report.LineRange{Start: int(e.Start), End: int(e.End)})
	}
}

// evalFailure names a failed reader call and says whether it ends the run.
func evalFailure(err error) (reason string, stop bool) {
	switch {
	case errors.Is(err, gateway.ErrBudgetExhausted):
		return string(report.SkipBudget), true
	case errors.Is(err, redact.ErrRunFull):
		return string(report.SkipRunFull), true
	case errors.Is(err, models.ErrInvalidOutput), errors.Is(err, reader.ErrEvidence):
		return reasonInvalidOutput, false
	}
	return string(report.SkipSendFailed), true
}
