package cli

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/planner"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/state"
	"github.com/sneakercreepers/creep/internal/static"
)

const (
	// replyTokens is each model reply's max_tokens.
	replyTokens = 1024
	// calibrationSeed fixes the calibration tasks, so every scan of one
	// model shares the cached tier (ADR 0009).
	calibrationSeed = 1
)

// session is one scan's open resources.
type session struct {
	cfg   config.Config
	opts  globalOptions
	deps  scanDeps
	store *state.Store
	run   *state.Run
	link  modelLink
	model *models.HTTP
	red   *redact.Redactor
	repo  *os.Root
	stats *runStats
}

// scanResult is what the pipeline decided, for the report.
type scanResult struct {
	findings []report.Finding
	gaps     []report.NotEvaluated
	stop     string // why the run stopped early, or ""
	planned  bool   // false when the planner refused the input or never ran
	noRoutes bool   // static extracted no route: no class was evaluated
	scanners scannerRun
}

// runScan scans the current directory: calibrate, static graph, plan,
// reader, report. Errors before a report exists exit 2 (or 3 for the
// model); afterwards the exit code is exitcode.ForReport, never 0 for an
// incomplete run (ADR 0007).
func runScan(e env, args []string) int {
	if len(args) > 1 || (len(args) == 1 && args[0] != ".") {
		printError(e.stderr, "creep scan", fmt.Errorf("scans the current directory; run it from the repository root (got %d arguments)", len(args)))
		return exitcode.ConfigError
	}
	resolved, err := loadConfig(e.opts)
	if err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
	// Only the scan deadline cancels the run's context (#260); it starts
	// after calibration, and the redactor stops with it.
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	s, err := openSession(ctx, e, resolved)
	if err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
	defer s.close()
	warnPreset(e.stderr, resolved.Config.Model)
	if err := s.checkTools(ctx); err != nil {
		printError(e.stderr, "creep scan: tool canary", err)
		return failureCode(err)
	}
	done := s.stats.start(phaseCalibrate)
	cal, err := s.calibrate(ctx)
	done()
	if err != nil {
		printError(e.stderr, "creep scan: calibration", err)
		return failureCode(err)
	}
	res, err := s.scanWithin(ctx, cancel, cal.Tier, e.stderr)
	if err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
	noteSandbox(context.WithoutCancel(ctx), e.stderr, s.deps.sandbox, s.cfg.Sandbox)
	return s.finish(e, cal, res)
}

// failureCode maps a model failure to its exit code: consent and other
// errors that carry their own code (2), anything else 3.
func failureCode(err error) int {
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return exitcode.ModelOrSandbox
}

// openSession checks the model settings before touching the disk, then
// opens the state store, a new run, the model link and the repository.
// The redactor stops with ctx.
func openSession(ctx context.Context, e env, r *config.Resolved) (*session, error) {
	if err := checkModelConfig(r.Config.Model); err != nil {
		return nil, err
	}
	s := &session{cfg: r.Config, opts: e.opts, deps: e.deps, stats: newRunStats(e.deps.now)}
	if err := s.openState(); err != nil {
		s.close()
		return nil, err
	}
	link, err := e.deps.connect(r, s.run.Dir(), e.stderr)
	if err != nil {
		s.close()
		return nil, err
	}
	s.link = link
	if err := s.openModel(ctx); err != nil {
		s.close()
		return nil, err
	}
	if s.repo, err = os.OpenRoot("."); err != nil {
		s.close()
		return nil, fmt.Errorf("open repository: %w", err)
	}
	return s, nil
}

func checkModelConfig(m config.Model) error {
	switch {
	case m.Contract == "command" && m.Run == "":
		return errors.New("model.run must be set for contract command (user config, --config, --model-run or CREEP_POLICY)")
	case m.Contract == "command":
		return nil
	case m.Contract != "openai" && m.Contract != "anthropic":
		return fmt.Errorf("model.contract %q is not supported by scan", m.Contract)
	case m.Endpoint == "" || m.Name == "":
		return errors.New("model.endpoint and model.name must be set (user config, --config or CREEP_POLICY)")
	}
	return nil
}

func (s *session) openState() error {
	var err error
	if s.store, err = state.OpenUser(stateDir); err != nil {
		return err
	}
	// The run holds the state lock: a second scan must fail on it before
	// it removes reports the first one is writing.
	if s.run, err = s.store.NewRun(s.mode()); err != nil {
		return err
	}
	return removeReports()
}

func (s *session) mode() state.Mode {
	switch {
	case s.opts.record:
		return state.ModeRecord
	case s.opts.replay:
		return state.ModeReplay
	}
	return state.ModeLive
}

func (s *session) openModel(ctx context.Context) error {
	send := s.stats.countRequests(recordedSend(s.store, s.mode(), s.stats.countSent(s.link.send)))
	opts, err := sessionModelOptions(s.cfg.Model, s.link.command, send)
	if err != nil {
		return err
	}
	if s.model, err = models.NewHTTP(opts); err != nil {
		return err
	}
	s.red, err = redact.NewWithContext(ctx)
	return err
}

// checkTools runs the tool canary once per run before calibration, so no
// repository text reaches a CLI that has tools. A replay starts no program.
func (s *session) checkTools(ctx context.Context) error {
	if s.mode() == state.ModeReplay {
		return nil
	}
	return checkTools(ctx, models.NewCanary(), s.cfg.Model, modelLink{send: s.stats.countSent(s.link.send), command: s.link.command})
}

// modelOptions are the scan's model settings. estimate measures requests
// with the same options, so its request bodies and cache keys are the ones
// the scan would send.
func modelOptions(m config.Model, key models.Key, send models.SendFunc) models.Options {
	structured := models.StructuredSchema
	if m.Contract == "anthropic" {
		structured = models.StructuredTools
	}
	return models.Options{
		Contract: m.Contract, Endpoint: m.Endpoint, Model: m.Name, Key: key,
		Structured: structured, MaxOutputTokens: replyTokens, Retries: 1, Send: send,
	}
}

func (s *session) close() {
	if s.repo != nil {
		_ = s.repo.Close()
	}
	if s.link.close != nil {
		_ = s.link.close()
	}
	if s.run != nil {
		_ = s.run.Close()
	}
	if s.store != nil {
		_ = s.store.Close()
	}
}

func (s *session) calibrate(ctx context.Context) (calibrate.Calibration, error) {
	return s.deps.calibrate(ctx, calibrate.CacheOptions{
		Options:     calibrate.Options{Seed: calibrationSeed, Model: s.model, Redactor: s.red},
		MaxAge:      time.Duration(s.cfg.Calibration.CacheDays) * 24 * time.Hour,
		Recalibrate: s.opts.recalibrate,
	})
}

// scan runs static analysis, the planner and the reader.
func (s *session) scan(ctx context.Context, tier calibrate.Tier) (scanResult, error) {
	ptier, err := plannerTier(tier)
	if err != nil {
		return scanResult{}, err
	}
	rtier, err := readerTier(tier)
	if err != nil {
		return scanResult{}, err
	}
	done := s.stats.start(phaseStatic)
	rs, err := s.walk(ctx)
	done()
	if err != nil {
		return scanResult{}, err
	}
	if len(rs.graph.Routes) == 0 {
		// No route means no sink either: there is nothing to plan or read.
		// A walk the deadline cut says nothing about the repository's
		// routes, so the run is not reported as having none (#260).
		return scanResult{gaps: rs.gaps, noRoutes: ctx.Err() == nil}, nil
	}
	findings := baseFindings(rs)
	done = s.stats.start(phasePlan)
	plan, err := planSinks(rs, ptier, planBudget(s.cfg.Budget.MaxTokens, rtier), findings)
	done()
	if errors.Is(err, planner.ErrInput) {
		return rejectedScan(findings, rs.gaps), nil
	}
	if err != nil {
		return scanResult{}, err
	}
	reads := newDeadlineReads(ctx, s.readRepo)
	stage := readStage{model: s.model, tier: rtier, reads: reads, slicer: reader.Slicer{Redactor: s.red, Tier: rtier, Read: reads.Read}}
	done = s.stats.start(phaseRead)
	gaps, stop, err := stage.run(ctx, plan, rs, findings)
	done()
	if err != nil {
		return scanResult{}, err
	}
	return scanResult{findings: findings, gaps: append(rs.gaps, gaps...), stop: stop, planned: true}, nil
}

// rejectedScan fails the scan closed when the planner refuses its input
// (planner.ErrInput, such as a graph over its 2^20 cap): nothing is
// evaluated, every sink is listed, and the run ends incomplete.
func rejectedScan(findings []report.Finding, gaps []report.NotEvaluated) scanResult {
	for i := range findings {
		findings[i].Reason = reasonPlannerRejected
	}
	return scanResult{findings: findings, gaps: gaps, stop: reasonPlannerRejected}
}

// walk starts the parser without the deadline, so a deadline that passes
// while the runtime starts cannot fail the run before a report exists; each
// parse still stops with ctx.
func (s *session) walk(ctx context.Context) (repoScan, error) {
	setup := context.WithoutCancel(ctx)
	p, err := static.NewParser(setup)
	if err != nil {
		return repoScan{}, err
	}
	defer p.Close(setup)
	return walkRepo(ctx, s.repo, p)
}

func (s *session) readRepo(path string) ([]byte, error) {
	return readInRoot(s.repo, path, static.MaxFileBytes)
}

// planBudget gives the planner the run's token budget and what one reader
// call can cost at the tier: its prompt and slice plus the reply.
func planBudget(maxTokens int, tier reader.Tier) planner.Budget {
	call, err := reader.CallTokens(tier)
	if err != nil {
		return planner.Budget{} // zero StepTokens: Build refuses it (fails closed)
	}
	tokens := uint32(0)
	if maxTokens > 0 {
		tokens = uint32(min(maxTokens, math.MaxUint32)) //nolint:gosec // G115: clamped to the uint32 range
	}
	return planner.Budget{Tokens: tokens, StepTokens: uint32(call + replyTokens)} //nolint:gosec // G115: a few thousand
}
