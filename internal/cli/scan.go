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
}

// scanResult is what the pipeline decided, for the report.
type scanResult struct {
	findings []report.Finding
	gaps     []report.NotEvaluated
	stop     string // why the run stopped early, or ""
	planned  bool   // false when the planner refused the input
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
	ctx := context.Background()
	s, err := openSession(e, resolved)
	if err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
	defer s.close()
	cal, err := s.calibrate(ctx)
	if err != nil {
		printError(e.stderr, "creep scan: calibration", err)
		return failureCode(err)
	}
	res, err := s.scan(ctx, cal.Tier)
	if err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
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
func openSession(e env, r *config.Resolved) (*session, error) {
	if err := checkModelConfig(r.Config.Model); err != nil {
		return nil, err
	}
	s := &session{cfg: r.Config, opts: e.opts, deps: e.deps}
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
	if err := s.openModel(); err != nil {
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
	case m.Contract != "openai" && m.Contract != "anthropic":
		return fmt.Errorf("model.contract %q is not supported by scan yet (the command contract is #6)", m.Contract)
	case m.Endpoint == "" || m.Name == "":
		return errors.New("model.endpoint and model.name must be set (user config, --config or CREEP_POLICY)")
	}
	return nil
}

func (s *session) openState() error {
	secret, err := state.UserSecret()
	if err != nil {
		return err
	}
	if s.store, err = state.Open(stateDir, secret); err != nil {
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

func (s *session) openModel() error {
	key, err := models.KeyFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	structured := models.StructuredSchema
	if s.cfg.Model.Contract == "anthropic" {
		structured = models.StructuredTools
	}
	s.model, err = models.NewHTTP(models.Options{
		Contract: s.cfg.Model.Contract, Endpoint: s.cfg.Model.Endpoint, Model: s.cfg.Model.Name, Key: key,
		Structured: structured, MaxOutputTokens: replyTokens, Retries: 1,
		Send: recordedSend(s.store, s.mode(), s.link.send),
	})
	if err != nil {
		return err
	}
	s.red, err = redact.New()
	return err
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
	rs, err := s.walk(ctx)
	if err != nil {
		return scanResult{}, err
	}
	findings := baseFindings(rs)
	plan, err := planSinks(rs, ptier, planBudget(s.cfg.Budget.MaxTokens, rtier), findings)
	if errors.Is(err, planner.ErrInput) {
		return rejectedScan(findings, rs.gaps), nil
	}
	if err != nil {
		return scanResult{}, err
	}
	stage := readStage{model: s.model, tier: rtier, slicer: reader.Slicer{Redactor: s.red, Tier: rtier, Read: s.readRepo}}
	gaps, stop, err := stage.run(ctx, plan, rs, findings)
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

func (s *session) walk(ctx context.Context) (repoScan, error) {
	p, err := static.NewParser(ctx)
	if err != nil {
		return repoScan{}, err
	}
	defer p.Close(ctx)
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
