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
	// reruns are the clients of --stability's samples 2 to N (ADR 0024).
	reruns []*models.HTTP
	red    *redact.Redactor
	repo   *os.Root
	stats  *runStats
	gate   runGate // the mode and the gate that judges the run (#28)
	// changed is the --changed list, nil for a full scan, and incremental
	// the scope the walk applied it with (#26).
	changed     *changedList
	incremental report.Incremental
	// baseline is --baseline, read before the run opened anything (#27).
	baseline *scanBaseline
	// staleReports are the report names the run could not remove when it
	// opened its state; the scan goes on and fails its exit code (#209).
	staleReports []error
}

// scanResult is what the pipeline decided, for the report.
type scanResult struct {
	findings []report.Finding
	gaps     []report.NotEvaluated
	stop     string // why the run stopped early, or ""
	planned  bool   // false when the planner refused the input or never ran
	disc     report.Discovery
	scanners scannerRun
	verify   report.Verification // the sandbox's outcome (#23)
	// slices holds the reader's slice behind each probable finding, by
	// finding index, for the PoC request (#25).
	slices map[int]reader.Slice
}

// runScan scans the current directory: walk, calibrate, discovery (the
// inventory, the tripwire and the model, ADR 0017), plan, reader, report.
// Errors before a report exists exit 2 (or 3 for the model); afterwards
// the exit code is exitcode.ForReport, never 0 for an incomplete run
// (ADR 0007).
func runScan(e env, args []string) int {
	in, err := loadScanInputs(e, args)
	if err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
	// Only the scan deadline cancels the run's context (#260); it starts
	// after calibration, and the redactor stops with it.
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	s, err := openSession(ctx, e, in)
	if err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
	defer s.close()
	warnPreset(e.stderr, in.resolved.Config.Model)
	files, scanned, err := s.walk(ctx, e.stderr)
	if err != nil {
		return s.fail(e, "creep scan", err, exitcode.ConfigError)
	}
	if err := s.checkTools(ctx); err != nil {
		return s.fail(e, "creep scan: tool canary", err, failureCode(err))
	}
	cal, err := s.calibrate(ctx)
	if err != nil {
		return s.fail(e, "creep scan: calibration", err, failureCode(err))
	}
	deadline := s.deps.sandbox.clock().Add(time.Duration(s.cfg.Budget.MaxSeconds) * time.Second)
	res, err := s.scanWithin(ctx, cancel, cal.Tier, scanned, e.stderr)
	if err != nil {
		return s.fail(e, "creep scan", err, exitcode.ConfigError)
	}
	res.verify = s.verifyApp(context.WithoutCancel(ctx), e.stderr, files, deadline, pocInput{tier: cal.Tier, res: &res})
	cal = s.feedStability(e.stderr, cal, res.findings)
	return s.finish(e, cal, res)
}

// scanInputs is what a scan reads and checks before it opens anything:
// the config, the gate of its mode, the --changed list and the baseline.
type scanInputs struct {
	resolved *config.Resolved
	gate     runGate
	changed  *changedList
	baseline *scanBaseline
}

// loadScanInputs reads the scan's inputs; any error is a usage or config
// error (exit 2), reported before a session, state or model is touched.
func loadScanInputs(e env, args []string) (scanInputs, error) {
	if len(args) > 1 || (len(args) == 1 && args[0] != ".") {
		return scanInputs{}, fmt.Errorf("scans the current directory; run it from the repository root (got %d arguments)", len(args))
	}
	var in scanInputs
	var err error
	if in.resolved, err = loadConfig(e.opts); err != nil {
		return scanInputs{}, err
	}
	if in.gate, err = chooseGate(e, in.resolved); err != nil {
		return scanInputs{}, err
	}
	if in.changed, err = e.changedList(); err != nil {
		return scanInputs{}, err
	}
	if in.baseline, err = loadScanBaseline(e.opts, e.deps.today()); err != nil {
		return scanInputs{}, err
	}
	return in, nil
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
func openSession(ctx context.Context, e env, in scanInputs) (*session, error) {
	r := in.resolved
	if err := checkModelConfig(r.Config.Model); err != nil {
		return nil, err
	}
	s := &session{cfg: r.Config, opts: e.opts, deps: e.deps, stats: newRunStats(e.deps.now),
		gate: in.gate, changed: in.changed, baseline: in.baseline}
	if err := s.openState(); err != nil {
		s.close()
		return nil, err
	}
	if err := s.connect(ctx, e, r); err != nil {
		s.close()
		return nil, err
	}
	var err error
	if s.repo, err = os.OpenRoot("."); err != nil {
		s.close()
		return nil, fmt.Errorf("open repository: %w", err)
	}
	return s, nil
}

// connect opens the model link into the run's directory, then the client
// and redactor every model call of the run goes through.
func (s *session) connect(ctx context.Context, e env, r *config.Resolved) error {
	link, err := e.deps.connect(r, s.run.Dir(), e.stderr)
	if err != nil {
		return err
	}
	s.link = link
	return s.openModel(ctx)
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
	// The run holds the state lock: a second scan must fail on it before
	// it removes reports the first one is writing.
	if err := s.openRun(); err != nil {
		return err
	}
	s.staleReports = removeReports(s.store.Root())
	return nil
}

// openRun opens the state store and a new run, which holds the state lock.
func (s *session) openRun() error {
	var err error
	if s.store, err = state.OpenUser(stateDir); err != nil {
		return err
	}
	s.run, err = s.store.NewRun(s.mode())
	return err
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
	var err error
	if s.model, err = s.sampleModel(1); err != nil {
		return err
	}
	if s.reruns, err = rerunModels(s.opts.stability, s.sampleModel); err != nil {
		return err
	}
	s.red, err = redact.NewWithContext(ctx)
	return err
}

// sampleModel is the client of one sample: every one goes through the
// run-state cache, the stats and the gateway, sample k's calls labeled
// for it (sampleSend).
func (s *session) sampleModel(k int) (*models.HTTP, error) {
	send := s.stats.countRequests(sampleSend(k, recordedSend(s.store, s.mode(), s.stats.countSent(s.link.send))))
	opts, err := sessionModelOptions(s.cfg.Model, s.link.command, send)
	if err != nil {
		return nil, err
	}
	return models.NewHTTP(opts)
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

// calibrate measures the model, or reads its cached tier, under the
// calibrate phase of --stats.
func (s *session) calibrate(ctx context.Context) (calibrate.Calibration, error) {
	defer s.stats.start(phaseCalibrate)()
	return s.deps.calibrate(ctx, calibrate.CacheOptions{
		Options:     calibrate.Options{Seed: calibrationSeed, Model: s.model, Redactor: s.red},
		MaxAge:      time.Duration(s.cfg.Calibration.CacheDays) * 24 * time.Hour,
		Recalibrate: s.opts.recalibrate,
	})
}

// scan runs discovery, the planner and the reader over the walked files.
func (s *session) scan(ctx context.Context, tier calibrate.Tier, files repoFiles) (scanResult, error) {
	rs, err := s.discover(ctx, tier, files)
	if err != nil {
		return scanResult{}, err
	}
	res, err := s.planAndRead(ctx, tier, rs)
	res.disc = rs.disc
	return res, err
}

// planAndRead plans every candidate and asks the reader about each
// hypothesis. A repository with no candidate plans nothing and reads
// nothing; whether that is complete is the files' to say (ADR 0017 D2).
func (s *session) planAndRead(ctx context.Context, tier calibrate.Tier, rs repoScan) (scanResult, error) {
	ptier, rtier, err := planReadTiers(tier)
	if err != nil {
		return scanResult{}, err
	}
	findings := baseFindings(rs)
	done := s.stats.start(phasePlan)
	plan, err := planSinks(rs, ptier, planBudget(s.cfg.Budget.MaxTokens, rtier, s.opts.stability), findings, s.deps.planned)
	done()
	if errors.Is(err, planner.ErrInput) {
		return rejectedScan(findings, rs.gaps), nil
	}
	if err != nil {
		return scanResult{}, err
	}
	reads := newDeadlineReads(ctx, readRepoFile(s.repo))
	stage := readStage{model: s.model, reruns: s.reruns, tier: rtier, reads: reads, slicer: reader.Slicer{Redactor: s.red, Tier: rtier, Read: reads.Read},
		kept: map[int]reader.Slice{}, votes: map[int]uint8{}}
	done = s.stats.start(phaseRead)
	gaps, stop, err := stage.run(ctx, plan, rs, findings)
	done()
	if err != nil {
		return scanResult{}, err
	}
	labelStability(findings, rs.res.Sinks, stage.votes, 1+len(s.reruns))
	return scanResult{findings: findings, gaps: append(rs.gaps, gaps...), stop: stop, planned: true, slices: stage.kept}, nil
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

// planBudget gives the planner the run's token budget and what one
// hypothesis can cost at the tier: its prompt and slice plus the reply,
// once per --stability sample, since every sample asks it (ADR 0024).
// Without that a stability run plans N times what the budget pays for and
// stops part way through the reader instead of skipping by budget.
func planBudget(maxTokens int, tier reader.Tier, samples int) planner.Budget {
	call, err := reader.CallTokens(tier)
	if err != nil {
		return planner.Budget{} // zero StepTokens: Build refuses it (fails closed)
	}
	tokens := uint32(0)
	if maxTokens > 0 {
		tokens = uint32(min(uint64(maxTokens), math.MaxUint32)) //nolint:gosec // G115: clamped to the uint32 range
	}
	step := (call + replyTokens) * min(max(samples, 1), maxStability)
	return planner.Budget{Tokens: tokens, StepTokens: uint32(step)} //nolint:gosec // G115: a few thousand, times at most maxStability
}
