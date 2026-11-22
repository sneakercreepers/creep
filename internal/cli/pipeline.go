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
// observe, when set, sees the input before the planner does.
func planSinks(rs repoScan, tier planner.Tier, budget planner.Budget, findings []report.Finding, observe func(planner.Input)) (planner.Plan, error) {
	in, unmapped := plannerInput(rs.res, tier, budget)
	if observe != nil {
		observe(in)
	}
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
	model *models.HTTP
	// reruns are --stability's samples 2 to N: each hypothesis is asked of
	// model and of every rerun (ADR 0024).
	reruns []*models.HTTP
	tier   reader.Tier
	slicer reader.Slicer // its Read is reads.Read
	reads  *deadlineReads
	// kept, when set, gets the slice behind each probable finding, by
	// finding index: the redacted code a PoC request shows the model (#25).
	kept map[int]reader.Slice
	// votes, when set, gets for each finding every sample answered the
	// samples whose answer was vulnerable, bit k for sample k+1.
	votes map[int]uint8
}

// run slices and evaluates every hypothesis. It returns the files the
// slicer could not use and the reason the run stopped early, if it did.
func (r readStage) run(ctx context.Context, plan planner.Plan, rs repoScan, findings []report.Finding) ([]report.NotEvaluated, string, error) {
	targets, sinkOf := targetsFor(plan, rs, findings)
	// Past the deadline the slicer still lists every file, without reading
	// it (deadlineReads), so a file discovery read but nothing sliced is in
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

// targetsFor turns hypotheses into reader targets. The route's first line
// is the source (the sink's own line for a file-level route) and the
// sink's line the sink; the path comes from the walk, by the sink's file
// ID. sinkOf maps a hypothesis to its finding index.
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
		source := int(route.Lines.Start)
		if route.FileLevel {
			// No entry point holds the sink: the slice starts from the sink
			// and walks back, not from line 1 of the file.
			source = int(sink.Line)
		}
		id := reader.HypothesisID(h.ID)
		targets = append(targets, reader.Target{
			Hypothesis: id, Class: class, Path: rs.paths[sink.File], SourceLine: source, SinkLine: int(sink.Line),
		})
		sinkOf[id] = at
	}
	return targets, sinkOf
}

// evaluate asks the model about each slice in plan order. A failure that
// ends the run (budget, the scan deadline, run_full, transport) marks this
// and every later hypothesis with its reason and returns it; a bad answer
// marks only its own hypothesis.
func (r readStage) evaluate(ctx context.Context, slices []reader.Slice, sinkOf map[reader.HypothesisID]int, findings []report.Finding) string {
	for i, s := range slices {
		at := sinkOf[s.Hypothesis]
		reason, stop := r.evaluateSamples(ctx, s, at, &findings[at])
		r.keep(at, s, findings[at])
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

// keep remembers the first slice that made finding at probable.
func (r readStage) keep(at int, s reader.Slice, f report.Finding) {
	if _, seen := r.kept[at]; r.kept == nil || seen || f.Status != report.StatusProbable {
		return
	}
	r.kept[at] = s
}

// evaluateSamples asks every sample about one slice, in sample order, and
// keeps the riskiest answer (readerRank): union only, so a sample can
// raise a finding and never lower it (ADR 0024). A sample that must stop
// the run stops it; the first sample's failure is the finding's, as with
// one sample, and a later one's leaves the answers before it. Only a
// finding every sample answered gets its votes.
func (r readStage) evaluateSamples(ctx context.Context, s reader.Slice, at int, f *report.Finding) (reason string, stop bool) {
	base := *f
	var votes uint8
	for k, m := range append([]*models.HTTP{r.model}, r.reruns...) {
		g := base
		reason, stop = r.evaluateOne(ctx, m, s, &g)
		if stop && k > 0 {
			return reason, true
		}
		if k == 0 || readerRank(g) > readerRank(*f) {
			*f = g
		}
		if stop {
			return reason, true
		}
		if g.Status == report.StatusProbable {
			votes |= 1 << k
		}
	}
	if r.votes != nil {
		r.votes[at] = votes
	}
	return "", false
}

// evaluateOne asks one sample's model about one slice and reports whether
// the run must stop. Past the deadline no call is made, and a call the
// deadline cut is named for it rather than for the transport error it
// surfaced as.
func (r readStage) evaluateOne(ctx context.Context, model *models.HTTP, s reader.Slice, f *report.Finding) (reason string, stop bool) {
	if pastDeadline(ctx, f) {
		return f.Reason, true
	}
	sig, err := reader.Evaluate(ctx, model, r.tier, s)
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
