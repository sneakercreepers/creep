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
)

// estimateTiers are the tiers estimate plans for: the tier comes from a
// calibration, so without a cached one every tier is shown.
var estimateTiers = []calibrate.Tier{calibrate.TierS, calibrate.TierM, calibrate.TierL}

// tierEstimate is what a scan at one tier would send.
type tierEstimate struct {
	tier       calibrate.Tier
	calibrated bool           // the cached calibration gives this tier
	requests   requestMeasure // discovery and reader requests
	discovery  requestMeasure // discovery requests alone
	wholeFiles int            // source files discovery sends whole
	candidates int            // tripwire candidates: the reader's floor
	skipped    map[string]int // sinks the plan or the slicer leaves out, by reason
	partial    int            // slices cut to fit the tier's budget
	incomplete string         // why the scan would end incomplete, or ""
}

// estimateRun is one estimate: the walk, the calibration and, per tier,
// discovery and a plan. Nothing in it is repository text except what
// discovery and the slicer read to measure request sizes, and none of
// that is printed.
type estimateRun struct {
	cfg   config.Config
	opts  globalOptions
	repo  *os.Root
	cache *state.Store // the run-state cache, or nil when .creep is missing
	files repoFiles
	seed  [32]byte // the stored discovery seed, so cached requests match
	cal   calibrationEstimate
	tiers []tierEstimate

	// changed is the --changed list, nil for a full scan, and incremental
	// the scope the walk applied it with (#26).
	changed     *changedList
	incremental report.Incremental
}

// runEstimate prints what `creep scan` would cost here without calling a
// model or opening a network connection (invariants 1, 2 and 5): the
// inventory, the discovery batches, the planner's plan over the tripwire's
// candidates and the exact request bodies the scan
// would build, measured by a send function that never sends (ADR 0011).
func runEstimate(e env, args []string) int {
	est, err := newEstimate(e, args)
	if err != nil {
		printError(e.stderr, "creep estimate", err)
		return exitcode.ConfigError
	}
	defer est.close()
	// The estimate reads and redacts the repository as scan does, so a
	// crafted file could hold it as long: budget.max_seconds bounds it too,
	// and a cut estimate fails closed (exit 4), never reading as whole.
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	stop := startDeadline(ctx, cancel, est.cfg.Budget.MaxSeconds)
	err = est.run(ctx, e.deps)
	cut := stop()
	if err != nil {
		printError(e.stderr, "creep estimate", err)
		return exitcode.ConfigError
	}
	printEstimate(e.stdout, est)
	if text := est.incremental.Text(est.files.gaps); text != "" {
		fmt.Fprintln(e.stdout, text)
	}
	if cut {
		fmt.Fprintf(e.stdout, "PARTIAL ESTIMATE: the deadline of %d s (budget.max_seconds) passed; files and sinks it did not reach are counted as not evaluated (reason %s), so the figures above are a lower bound\n", est.cfg.Budget.MaxSeconds, reasonDeadline)
		return exitcode.Incomplete
	}
	return exitcode.OK
}

// newEstimate checks the arguments and opens the estimate; any error is a
// usage or config error (exit 2).
func newEstimate(e env, args []string) (*estimateRun, error) {
	if len(args) > 1 || (len(args) == 1 && args[0] != ".") {
		return nil, fmt.Errorf("estimates a scan of the current directory; run it from the repository root (got %d arguments)", len(args))
	}
	if e.opts.explicit["format"] && e.opts.format != "text" {
		return nil, fmt.Errorf("prints text only, not --format %q", e.opts.format)
	}
	resolved, err := loadConfig(e.opts)
	if err != nil {
		return nil, err
	}
	est := &estimateRun{cfg: resolved.Config, opts: e.opts}
	if est.changed, err = readChangedList(e.opts.changed); err != nil {
		return nil, err
	}
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
	return state.OpenUser(stateDir)
}

func (est *estimateRun) run(ctx context.Context, deps scanDeps) error {
	// Calibration (no repository text) runs without the deadline; each
	// redaction and each discovery or reader read stops with ctx.
	setup := context.WithoutCancel(ctx)
	var err error
	if est.files, err = walkRepo(ctx, est.repo); err != nil {
		return err
	}
	est.files, est.incremental = est.changed.scope(est.files)
	if est.seed, err = storedSeed(est.cache); err != nil {
		return err
	}
	if est.cal, err = est.calibration(setup, deps); err != nil {
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

// tier measures the scan at one tier, as scan runs it: discovery, then the
// plan over its candidates and each reader request the plan leads to.
func (est *estimateRun) tier(ctx context.Context, tier calibrate.Tier) (tierEstimate, error) {
	t := tierEstimate{tier: tier, calibrated: est.cal.cached && est.cal.tier == tier, skipped: map[string]int{}}
	red, err := redact.NewWithContext(ctx)
	if err != nil {
		return t, err
	}
	rs, err := est.measureDiscovery(ctx, tier, red, &t)
	if err != nil {
		return t, err
	}
	ptier, rtier, err := planReadTiers(tier)
	if err != nil {
		return t, err
	}
	findings := baseFindings(rs)
	plan, err := planSinks(rs, ptier, planBudget(est.cfg.Budget.MaxTokens, rtier), findings, nil)
	if errors.Is(err, planner.ErrInput) {
		return t.rejected(findings, rs.gaps), nil
	}
	if err != nil {
		return t, err
	}
	stop, err := est.measureReads(ctx, red, rtier, plan, rs, findings, &t)
	if err != nil {
		return t, err
	}
	if stop == "" && ctx.Err() != nil {
		stop = reasonDeadline // the deadline cut this tier's slicing
	}
	countSkipped(findings, t.skipped)
	t.incomplete = incompleteReason(stop, findings, rs.gaps)
	return t, nil
}

// rejected is the estimate of a scan whose planner refuses its input: as
// the scan, nothing is read, every sink is skipped and the run incomplete.
func (t tierEstimate) rejected(findings []report.Finding, gaps []report.NotEvaluated) tierEstimate {
	r := rejectedScan(findings, gaps)
	t.skipped[reasonPlannerRejected] = len(r.findings)
	t.incomplete = r.stop
	return t
}

// measureReads builds every slice as the scan would and measures the
// request each one becomes. A sliced finding is marked discarded only so
// incompleteReason sees it as answered: the estimate predicts which sinks
// cannot be evaluated, not what the model will say.
func (est *estimateRun) measureReads(ctx context.Context, red *redact.Redactor, rtier reader.Tier, plan planner.Plan, rs repoScan, findings []report.Finding, t *tierEstimate) (string, error) {
	targets, sinkOf := targetsFor(plan, rs, findings)
	rep, err := est.slice(ctx, red, rtier, targets)
	if err != nil {
		return "", err
	}
	for _, n := range rep.NotEvaluated {
		findings[sinkOf[n.Hypothesis]].Reason = string(n.Reason)
	}
	m := &meter{cache: est.cache}
	// Metering builds requests in memory only; the slices are already made.
	if err := m.readerRequests(context.WithoutCancel(ctx), est.cfg.Model, rtier, rep.Slices, est.opts.stability); err != nil {
		return "", err
	}
	t.requests = t.requests.plus(m.requestMeasure)
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

// slice builds the tier's slices as the scan would, under the deadline:
// the redactor stops with ctx, and files the slicer never reached are listed
// as budget, unread.
func (est *estimateRun) slice(ctx context.Context, red *redact.Redactor, rtier reader.Tier, targets []reader.Target) (reader.SliceReport, error) {
	reads := newDeadlineReads(ctx, readRepoFile(est.repo))
	rep, err := reader.Slicer{Redactor: red, Tier: rtier, Read: reads.Read}.Build(targets)
	if err != nil && !rep.Incomplete {
		return rep, err
	}
	reads.relabel(&rep, targets)
	return rep, nil
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
