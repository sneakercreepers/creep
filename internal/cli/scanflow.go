package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

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
	// The scan deadline (#260) or an MCP call the agent called off ends
	// the run's context; the deadline starts after calibration, and the
	// redactor stops with it.
	ctx, cancel := context.WithCancelCause(e.parent())
	defer cancel(nil)
	s, err := openSession(ctx, e, in, (*session).openState)
	if err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
	defer s.close()
	return s.runPipeline(ctx, cancel, e)
}

// runPipeline is the scan once its session is open, the same for a new
// run and a resumed one (#335): a resumed run's finished steps are served
// from its recordings (session.respond), so it reaches the report an
// uninterrupted run would.
func (s *session) runPipeline(ctx context.Context, cancel context.CancelCauseFunc, e env) int {
	s.cancel = cancel
	warnPreset(e.stderr, s.cfg.Model)
	files, scanned, err := s.walk(ctx, e.stderr)
	if err != nil {
		return s.fail(e, "creep scan", err, exitcode.ConfigError)
	}
	if err := s.stepFiles(files); err != nil {
		return s.fail(e, refusalPrefix(err), err, exitcode.ConfigError)
	}
	cal, prefix, err := s.toolsAndCalibration(ctx)
	if err != nil {
		return s.failStage(e, prefix, err, failureCode(err))
	}
	if err := s.checkRecipes(ctx, cal.Tier, e.stderr); err != nil {
		return s.failStage(e, "creep scan: recipes", err, recipeFailureCode(err))
	}
	s.scanStart = s.deps.sandbox.clock()
	deadline := s.scanStart.Add(s.timeLeft())
	res, err := s.scanWithin(ctx, cancel, cal.Tier, scanned, e.stderr)
	if err != nil || s.refused != nil {
		return s.failStage(e, "creep scan", err, exitcode.ConfigError)
	}
	res.verify = s.verifyApp(context.WithoutCancel(ctx), e.stderr, files, deadline, pocInput{tier: cal.Tier, res: &res})
	if s.refused != nil {
		return s.failStage(e, "creep scan", nil, exitcode.ConfigError)
	}
	cal = s.feedStability(e.stderr, cal, res.findings)
	return s.finish(e, cal, res)
}

// failStage is fail for a stage that may have met a resume refusal
// (session.refuse): the refusal wins, exits 2 and leaves no end line, so
// no report mixes recordings the run did not get.
func (s *session) failStage(e env, prefix string, err error, code int) int {
	if s.refused != nil {
		return s.fail(e, "creep resume", s.refused, exitcode.ConfigError)
	}
	return s.fail(e, prefix, err, code)
}

// toolsAndCalibration runs the tool canary and calibration, and returns
// the error prefix of what failed. A resumed run that already calibrated
// reads that calibration from the cache only, before the canary, so a
// changed tier is refused with nothing sent (#335).
func (s *session) toolsAndCalibration(ctx context.Context) (calibrate.Calibration, string, error) {
	tier, resumed := s.resumed.step(tierStep)
	var cal calibrate.Calibration
	if resumed {
		var err error
		if cal, err = s.resumedCalibration(ctx, tier); err != nil {
			return cal, "creep resume", err
		}
	}
	if err := s.checkTools(ctx); err != nil {
		return cal, "creep scan: tool canary", err
	}
	if resumed {
		return cal, "", nil
	}
	cal, err := s.calibrate(ctx)
	if err != nil {
		return cal, "creep scan: calibration", err
	}
	if err := s.record(tierStep + string(cal.Tier)); err != nil {
		return cal, "creep scan", err
	}
	return cal, "", nil
}

// scanInputs is what a scan reads and checks before it opens anything:
// the config, the gate of its mode, the --changed list, the baseline and
// the installed recipes, verified against creep.lock (ADR 0028).
type scanInputs struct {
	resolved *config.Resolved
	gate     runGate
	changed  *changedList
	baseline *scanBaseline
	recipes  []installedRecipe
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
	if in.recipes, err = loadInstalledRecipes(in.resolved); err != nil {
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
