package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sneakercreepers/creep/internal/bench"
	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/redact"
)

// errBenchReplayCalibration: the published fixture holds corpus replies
// only, so a replayed bench has no calibration to measure.
var errBenchReplayCalibration = errors.New("--recalibrate measures a live calibration; the published fixture has none, so it cannot be used with --replay")

// optionalCalibration measures a calibration first when --recalibrate
// asks for one, within limit, and is nil otherwise: the bench forces each
// tier.
func (b *benchLive) optionalCalibration(e env, cfg config.Model, limit time.Duration) (*bench.CalibrationCost, error) {
	if !e.opts.recalibrate {
		return nil, nil
	}
	fmt.Fprintf(e.stderr, "creep bench: calibrates the model first (--recalibrate): %d tasks and the tool and context probes, redacted, to endpoint %s\n",
		calibrate.TaskCount, escapeControl(cfg.Endpoint))
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	return b.measureCalibration(ctx, cfg)
}

// measureCalibration runs one real calibration of the configured model for
// bench --recalibrate (#363) and returns its cost: the calls, tokens and
// wall time a first scan pays before it reads any file. It goes through
// the gateway (consent, budget, egress.log) but not through the fixture
// recorder, so the fixture stays corpus replies only, and it never reads
// or writes the calibration cache: the bench measures, it does not keep.
func (b *benchLive) measureCalibration(ctx context.Context, cfg config.Model) (*bench.CalibrationCost, error) {
	st := newRunStats(nil)
	opts, err := sessionModelOptions(cfg, nil, st.countRequests(st.countSent(b.link.send)))
	if err != nil {
		return nil, err
	}
	m, err := models.NewHTTP(opts)
	if err != nil {
		return nil, err
	}
	red, err := redact.NewWithContext(ctx)
	if err != nil {
		return nil, err
	}
	done := st.start(phaseCalibrate)
	r, err := calibrate.Run(ctx, calibrate.Options{Seed: calibrationSeed, Model: m, Redactor: red})
	done()
	if err != nil {
		return nil, fmt.Errorf("calibration: %w", err)
	}
	return st.calibrationCost().benchCost(r), nil
}
