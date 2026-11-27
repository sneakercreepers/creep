package cli

import (
	"context"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/state"
)

// maxStability is the most samples --stability takes: each one repeats
// every discovery and reader call, so it multiplies the scan's cost.
const maxStability = discover.MaxSamples

// stabilityCommands are the commands --stability changes; any other one
// refuses it rather than ignore it.
var stabilityCommands = map[string]bool{"scan": true, "estimate": true, "resume": true}

func checkStabilityFlag(command string, opts globalOptions) error {
	switch {
	case !opts.explicit["stability"]:
		return nil
	case opts.stability < 1 || opts.stability > maxStability:
		return fmt.Errorf("--stability %d: want 1 to %d runs", opts.stability, maxStability)
	case !stabilityCommands[command]:
		return fmt.Errorf("--stability changes only scan, resume and estimate, not %s", command)
	}
	return nil
}

// sampleSend labels sample k's calls (k from 1): the first keeps its
// purpose, so a run without --stability sends and records exactly what it
// did before, and sample k > 1 is "<purpose>-s<k>". The label is part of
// the call, so egress.log names each sample and the run-state cache keys
// each sample's answer apart: a live run asks the model again instead of
// serving sample 1's answer, and --replay serves each sample its own
// recording (ADR 0024).
func sampleSend(k int, send models.SendFunc) models.SendFunc {
	if k <= 1 {
		return send
	}
	return func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
		c.Purpose = fmt.Sprintf("%s-s%d", c.Purpose, k)
		return send(ctx, c)
	}
}

// rerunModels builds the clients of samples 2 to n, each on its own
// labeled send function: newModel gets the sample number.
func rerunModels(n int, newModel func(sample int) (*models.HTTP, error)) ([]*models.HTTP, error) {
	var out []*models.HTTP
	for k := 2; k <= n; k++ {
		m, err := newModel(k)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// readerRank orders a sample's answer by the risk it leaves: probable
// over undecided over discarded. The answer a finding keeps is the
// riskiest of its samples, so a sample can raise a finding, never lower it.
func readerRank(f report.Finding) int {
	switch f.Status {
	case report.StatusProbable:
		return 2
	case report.StatusDiscarded:
		return 0
	}
	return 1
}

// labelStability gives each probable finding of a --stability run its
// stability: of the run's samples, those whose discovery named the sink
// and whose reader answered vulnerable. votes holds, by finding index,
// the samples whose reader answered vulnerable, only for findings every
// sample answered. It labels; it never changes a status.
func labelStability(findings []report.Finding, sinks []discover.Sink, votes map[int]uint8, samples int) {
	if samples < 2 {
		return
	}
	for at, v := range votes {
		f := &findings[at]
		if f.Status != report.StatusProbable || at >= len(sinks) {
			continue
		}
		f.Stability = report.NewStability(bits.OnesCount8(sinks[at].SeenBy&v), samples)
	}
}

// classStability counts, per calibrated class, the findings a stability
// run labeled and how many of them were unstable discoveries.
func classStability(findings []report.Finding) map[calibrate.Class]calibrate.ClassStability {
	out := map[calibrate.Class]calibrate.ClassStability{}
	for _, f := range findings {
		class := calibrate.Class(f.Class)
		if f.Stability == nil || !slices.Contains(calibrate.Classes(), class) {
			continue
		}
		c := out[class]
		c.Findings++
		if f.Stability.Unstable {
			c.Unstable++
		}
		out[class] = c
	}
	return out
}

// feedStability adds a live or recorded stability run's counts to the
// model's calibration record and returns the calibration with the new
// record, for its line in the summary. --replay never writes it, so a
// replay reproduces the run without changing what later scans read. A
// record that cannot be written is a warning, never a failed scan.
func (s *session) feedStability(w io.Writer, cal calibrate.Calibration, findings []report.Finding) calibrate.Calibration {
	seen := classStability(findings)
	// An unfit model run past the floor never feeds the record (ADR 0036).
	off := s.opts.stability < 2 || s.mode() == state.ModeReplay || s.cfg.Calibration.CacheDays <= 0 || !cal.Fitness.Fit
	if off || len(seen) == 0 || s.deps.recordStability == nil {
		return cal
	}
	rec, err := s.deps.recordStability(calibrate.CacheOptions{
		Options: calibrate.Options{Seed: calibrationSeed, Model: s.model, Redactor: s.red},
		MaxAge:  time.Duration(s.cfg.Calibration.CacheDays) * 24 * time.Hour,
	}, seen)
	if err != nil {
		printError(w, "creep scan: stability record", err)
		return cal
	}
	cal.Stability = rec
	return cal
}

// recordStabilityInUserCache keeps the stability record beside the
// calibration it notes, in the user's cache directory.
func recordStabilityInUserCache(opts calibrate.CacheOptions, seen map[calibrate.Class]calibrate.ClassStability) (map[calibrate.Class]calibrate.ClassStability, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	store, err := state.OpenUser(filepath.Join(base, "creep"))
	if err != nil {
		return nil, err
	}
	defer store.Close()
	opts.Store, opts.Now = store, time.Now
	return calibrate.RecordStability(opts, seen)
}
