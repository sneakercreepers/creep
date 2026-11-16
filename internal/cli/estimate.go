package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/planner"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/state"
	"github.com/sneakercreepers/creep/internal/static"
)

// estimateTiers are the tiers estimate plans for: the tier comes from a
// calibration, so without a cached one every tier is shown.
var estimateTiers = []calibrate.Tier{calibrate.TierS, calibrate.TierM, calibrate.TierL}

// tierEstimate is what a scan at one tier would send.
type tierEstimate struct {
	tier       calibrate.Tier
	calibrated bool           // the cached calibration gives this tier
	requests   requestMeasure // reader requests
	skipped    map[string]int // sinks the plan or the slicer leaves out, by reason
	partial    int            // slices cut to fit the tier's budget
	incomplete string         // why the scan would end incomplete, or ""
}

// estimateRun is one estimate: the static view, the calibration and one
// plan per tier. Nothing in it is repository text except what the slicer
// reads to measure request sizes, and none of that is printed.
type estimateRun struct {
	cfg   config.Config
	opts  globalOptions
	repo  *os.Root
	cache *state.Store // the run-state cache, or nil when .creep is missing
	scan  repoScan
	cal   calibrationEstimate
	tiers []tierEstimate
}

// runEstimate prints what `creep scan` would cost here without calling a
// model or opening a network connection (invariants 1, 2 and 5): the
// static graph, the planner's plan and the exact request bodies the scan
// would build, measured by a send function that never sends (ADR 0010).
func runEstimate(e env, args []string) int {
	if len(args) > 1 || (len(args) == 1 && args[0] != ".") {
		printError(e.stderr, "creep estimate", fmt.Errorf("estimates a scan of the current directory; run it from the repository root (got %d arguments)", len(args)))
		return exitcode.ConfigError
	}
	if e.opts.explicit["format"] && e.opts.format != "text" {
		printError(e.stderr, "creep estimate", fmt.Errorf("prints text only, not --format %q", e.opts.format))
		return exitcode.ConfigError
	}
	est, err := newEstimate(e)
	if err != nil {
		printError(e.stderr, "creep estimate", err)
		return exitcode.ConfigError
	}
	defer est.close()
	if err := est.run(context.Background(), e.deps); err != nil {
		printError(e.stderr, "creep estimate", err)
		return exitcode.ConfigError
	}
	printEstimate(e.stdout, est)
	return exitcode.OK
}

func newEstimate(e env) (*estimateRun, error) {
	resolved, err := loadConfig(e.opts)
	if err != nil {
		return nil, err
	}
	est := &estimateRun{cfg: resolved.Config, opts: e.opts}
	if est.cache, err = openCacheReadOnly(); err != nil {
		return nil, err
	}
	if est.repo, err = os.OpenRoot("."); err != nil {
		est.close()
		return nil, fmt.Errorf("open repository: %w", err)
	}
	return est, nil
}

func (est *estimateRun) close() {
	if est.repo != nil {
		_ = est.repo.Close()
	}
	if est.cache != nil {
		_ = est.cache.Close()
	}
}

// openCacheReadOnly opens .creep for cache lookups, or returns nil when it
// does not exist: estimate never creates the state directory.
func openCacheReadOnly() (*state.Store, error) {
	if _, err := os.Lstat(stateDir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	secret, err := state.UserSecret()
	if err != nil {
		return nil, err
	}
	return state.Open(stateDir, secret)
}

func (est *estimateRun) run(ctx context.Context, deps scanDeps) error {
	p, err := static.NewParser(ctx)
	if err != nil {
		return err
	}
	est.scan, err = walkRepo(ctx, est.repo, p)
	p.Close(ctx)
	if err != nil {
		return err
	}
	if est.cal, err = est.calibration(ctx, deps); err != nil {
		return err
	}
	for _, tier := range estimateTiers {
		t, err := est.tier(ctx, tier)
		if err != nil {
			return err
		}
		est.tiers = append(est.tiers, t)
	}
	return nil
}

// tier plans the scan at one tier, as scan does, and measures each reader
// request the plan leads to.
func (est *estimateRun) tier(ctx context.Context, tier calibrate.Tier) (tierEstimate, error) {
	t := tierEstimate{tier: tier, calibrated: est.cal.cached && est.cal.tier == tier, skipped: map[string]int{}}
	ptier, err := plannerTier(tier)
	if err != nil {
		return t, err
	}
	rtier, err := readerTier(tier)
	if err != nil {
		return t, err
	}
	findings := baseFindings(est.scan)
	plan, err := planSinks(est.scan, ptier, planBudget(est.cfg.Budget.MaxTokens, rtier), findings)
	if errors.Is(err, planner.ErrInput) {
		rejected := rejectedScan(findings, est.scan.gaps)
		t.skipped[reasonPlannerRejected] = len(rejected.findings)
		t.incomplete = rejected.stop
		return t, nil
	}
	if err != nil {
		return t, err
	}
	stop, err := est.measureReads(ctx, rtier, plan, findings, &t)
	if err != nil {
		return t, err
	}
	countSkipped(findings, t.skipped)
	t.incomplete = incompleteReason(stop, findings, est.scan.gaps)
	return t, nil
}

// measureReads builds every slice as the scan would and measures the
// request each one becomes. A sliced finding is marked discarded only so
// incompleteReason sees it as answered: the estimate predicts which sinks
// cannot be evaluated, not what the model will say.
func (est *estimateRun) measureReads(ctx context.Context, rtier reader.Tier, plan planner.Plan, findings []report.Finding, t *tierEstimate) (string, error) {
	red, err := redact.New()
	if err != nil {
		return "", err
	}
	targets, sinkOf := targetsFor(plan, est.scan, findings)
	slicer := reader.Slicer{Redactor: red, Tier: rtier, Read: func(path string) ([]byte, error) {
		return readInRoot(est.repo, path, static.MaxFileBytes)
	}}
	rep, err := slicer.Build(targets)
	if err != nil && !rep.Incomplete {
		return "", err
	}
	for _, n := range rep.NotEvaluated {
		findings[sinkOf[n.Hypothesis]].Reason = string(n.Reason)
	}
	m := &meter{cache: est.cache}
	if err := m.readerRequests(ctx, est.cfg.Model, rtier, rep.Slices); err != nil {
		return "", err
	}
	t.requests = m.requestMeasure
	for _, s := range rep.Slices {
		f := &findings[sinkOf[s.Hypothesis]]
		f.Status, f.Partial = report.StatusDiscarded, s.Partial
		if s.Partial {
			t.partial++
		}
	}
	if rep.Incomplete {
		return string(report.SkipRunFull), nil
	}
	return "", nil
}

// countSkipped counts the sinks that stay not evaluated, by reason.
func countSkipped(findings []report.Finding, into map[string]int) {
	for _, f := range findings {
		if f.Status != report.StatusNotEvaluated {
			continue
		}
		reason := f.Reason
		if reason == "" {
			reason = reasonNotEvaluated
		}
		into[reason]++
	}
}
