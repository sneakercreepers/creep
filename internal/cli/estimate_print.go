package cli

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// printEstimate writes the estimate. It prints counts, tiers and reason
// IDs only, never a path or other repository text, so nothing from the
// scanned code can reach the terminal through it.
func printEstimate(w io.Writer, est *estimateRun) {
	fmt.Fprintln(w, "estimate: no model was called and no connection was opened")
	fmt.Fprintf(w, "walk: %d files, up to %d source files go to discovery whole and redacted; %d files listed without reading\n",
		len(est.files.paths), est.files.sources(), len(est.files.gaps))
	fmt.Fprintf(w, "calibration: %s\n", est.calibrationLine())
	if n := est.opts.stability; n > 1 {
		fmt.Fprintf(w, "stability: %d runs; every discovery and reader call below is made %d times, each its own call and recording\n", n, n)
	}
	price := pricingFor(est.opts, est.cfg.Model.Contract)
	fmt.Fprintf(w, "%-6s %6s %7s %10s %10s %9s\n", "tier", "calls", "cached", "tokens in", "tokens out", "time")
	for _, t := range est.tiers {
		r := est.rowMeasure(t)
		fmt.Fprintf(w, "%-6s %6d %7d %10d %10d %9s\n", tierLabel(t), r.calls, r.cached, r.inputTokens(), r.outputTokens(), r.duration())
	}
	for _, t := range est.tiers {
		est.printTierNotes(w, t, price)
	}
	fmt.Fprintf(w, "assumes ~%.1f bytes per token, ~%d output tokens per reply and ~%ds per call (a hosted model; a local CPU model measured ~%ds), one call at a time; cached calls are served from .creep/cache and cost nothing\n",
		float64(bytesPerTenTokens)/10, replyEstimateTokens, callSeconds, cpuCallSeconds)
}

// rowMeasure is a tier's requests plus calibration when the scan must run it.
func (est *estimateRun) rowMeasure(t tierEstimate) requestMeasure {
	if est.cal.cached {
		return t.requests
	}
	return t.requests.plus(est.cal.requests)
}

func (est *estimateRun) calibrationLine() string {
	if est.cal.cached {
		return fmt.Sprintf("cached, tier %s (marked *)", est.cal.tier)
	}
	r := est.cal.requests
	cpu := time.Duration(r.live()) * cpuCallSeconds * time.Second
	return fmt.Sprintf("not cached: the scan calibrates first, at least %d calls (~%d tokens in, ~%s at %ds per call, ~%s on a local CPU model), included in every tier; the tier it measures is not known yet",
		r.calls, r.inputTokens(), r.duration(), callSeconds, cpu)
}

func tierLabel(t tierEstimate) string {
	if t.calibrated {
		return string(t.tier) + " *"
	}
	return string(t.tier)
}

// printTierNotes prints a tier's cost, what it leaves out and the budget
// checks the gateway will apply.
func (est *estimateRun) printTierNotes(w io.Writer, t tierEstimate, price pricing) {
	r := est.rowMeasure(t)
	fmt.Fprintf(w, "tier %s: cost %s\n", t.tier, price.cost(r.inputTokens(), r.outputTokens()))
	fmt.Fprintf(w, "  discovery: %d calls send %d whole source files; the reader plans %d tripwire candidates (the model may propose more)\n",
		t.discovery.calls, t.wholeFiles, t.candidates)
	if len(t.skipped) > 0 {
		fmt.Fprintf(w, "  sinks not evaluated: %s\n", reasonCounts(t.skipped))
	}
	if t.partial > 0 {
		fmt.Fprintf(w, "  %d slices cut to fit the tier's budget (partial verdicts)\n", t.partial)
	}
	for _, line := range est.budgetWarnings(r) {
		fmt.Fprintf(w, "  %s\n", line)
	}
	if t.incomplete != "" {
		fmt.Fprintf(w, "  the scan would end incomplete (reason %s, exit 4)\n", t.incomplete)
	}
}

// budgetWarnings compares the requests with budget.max_tokens and
// budget.max_calls, which the gateway enforces on uncached calls.
func (est *estimateRun) budgetWarnings(r requestMeasure) []string {
	var out []string
	b := est.cfg.Budget
	if b.MaxTokens > 0 && r.reserve > b.MaxTokens {
		out = append(out, fmt.Sprintf("the gateway reserves up to %d tokens, over budget.max_tokens %d: the scan may stop early (budget, exit 4)", r.reserve, b.MaxTokens))
	}
	if b.MaxCalls > 0 && r.live() > b.MaxCalls {
		out = append(out, fmt.Sprintf("%d uncached calls, over budget.max_calls %d: the scan stops after %d (budget, exit 4)", r.live(), b.MaxCalls, b.MaxCalls))
	}
	return out
}

// reasonCounts lists counts by reason ID in name order.
func reasonCounts(counts map[string]int) string {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	slices.Sort(names)
	parts := make([]string, len(names))
	for i, name := range names {
		parts[i] = fmt.Sprintf("%d %s", counts[name], escapeControl(name))
	}
	return strings.Join(parts, ", ")
}
