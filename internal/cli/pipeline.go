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
	"github.com/sneakercreepers/creep/internal/static"
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
	// reasonNoRoutes: static extracted no route at all (a Django-only or
	// empty repository), so nothing was evaluated for any class (#207).
	reasonNoRoutes = "no_routes"
)

// baseFindings has one finding per sink, indexed by sink ID, each not
// evaluated until a stage decides it: a sink no stage reaches stays listed.
func baseFindings(rs repoScan) []report.Finding {
	out := make([]report.Finding, len(rs.graph.Sinks))
	for i, s := range rs.graph.Sinks {
		route := rs.graph.Routes[s.Route]
		out[i] = report.Finding{
			ID: fmt.Sprintf("sink-%d", s.ID), Class: kindClass(s.Kind), Status: report.StatusNotEvaluated,
			Path: rs.locs.Files[route.File], Line: rs.locs.Sinks[i].Line,
		}
	}
	return out
}

// planSinks builds the plan and records every sink it leaves out, with its
// reason. planner.ErrInput is returned for the caller to fail closed.
func planSinks(rs repoScan, tier planner.Tier, budget planner.Budget, findings []report.Finding) (planner.Plan, error) {
	in, unmapped := plannerInput(rs.graph, tier, budget)
	for _, id := range unmapped {
		findings[id].Reason = reasonUnmappedKind
	}
	plan, err := planner.Build(in)
	if err != nil {
		return planner.Plan{}, err
	}
	for _, s := range plan.Skipped {
		findings[s.Sink].Reason = skipName(s.Reason)
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
	slicer reader.Slicer // its Read is reads.Read
	reads  *deadlineReads
}

// run slices and evaluates every hypothesis. It returns the files the
// slicer could not use and the reason the run stopped early, if it did.
func (r readStage) run(ctx context.Context, plan planner.Plan, rs repoScan, findings []report.Finding) ([]report.NotEvaluated, string, error) {
	targets, sinkOf := targetsFor(plan, rs, findings)
	// Past the deadline the slicer still lists every file, without reading
	// it (deadlineReads), so a file static parsed but nothing sliced is in
	// coverage too.
	rep, err := r.slicer.Build(targets)
	if err != nil && !rep.Incomplete {
		return nil, "", err
	}
	r.reads.relabel(&rep, targets)
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

// targetsFor turns hypotheses into reader targets; static IDs index the
// graph and locations directly.
func targetsFor(plan planner.Plan, rs repoScan, findings []report.Finding) ([]reader.Target, map[reader.HypothesisID]static.SinkID) {
	targets := make([]reader.Target, 0, len(plan.Hypotheses))
	sinkOf := make(map[reader.HypothesisID]static.SinkID, len(plan.Hypotheses))
	for _, h := range plan.Hypotheses {
		class, err := readerClass(h.Class)
		if err != nil {
			findings[h.Sink].Reason = reasonUnmappedClass
			continue
		}
		route := rs.graph.Routes[h.Route]
		id := reader.HypothesisID(h.ID)
		targets = append(targets, reader.Target{
			Hypothesis: id, Class: class, Path: rs.locs.Files[route.File],
			SourceLine: rs.locs.Routes[h.Route].Line, SinkLine: rs.locs.Sinks[h.Sink].Line,
		})
		sinkOf[id] = static.SinkID(h.Sink)
	}
	return targets, sinkOf
}

// evaluate asks the model about each slice in plan order. A failure that
// ends the run (budget, the scan deadline, run_full, transport) marks this
// and every later hypothesis with its reason and returns it; a bad answer
// marks only its own hypothesis.
func (r readStage) evaluate(ctx context.Context, slices []reader.Slice, sinkOf map[reader.HypothesisID]static.SinkID, findings []report.Finding) string {
	for i, s := range slices {
		reason, stop := r.evaluateOne(ctx, s, &findings[sinkOf[s.Hypothesis]])
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

// evaluateOne asks about one slice and reports whether the run must stop.
// Past the deadline no call is made, and a call the deadline cut is named
// for it rather than for the transport error it surfaced as.
func (r readStage) evaluateOne(ctx context.Context, s reader.Slice, f *report.Finding) (reason string, stop bool) {
	if pastDeadline(ctx, f) {
		return f.Reason, true
	}
	sig, err := reader.Evaluate(ctx, r.model, r.tier, s)
	if err == nil {
		applySignal(f, sig)
		return "", false
	}
	if pastDeadline(ctx, f) {
		return f.Reason, true
	}
	reason, stop = evalFailure(err)
	f.Reason = reason
	return reason, stop
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
