package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/state"
)

// Step IDs a scan records in its run state (#335). Each is an ID or a
// digest, never repository text.
const (
	filesStep = "files:" // the digest of the walked files and what the scan can read of them
	tierStep  = "tier:"  // the calibrated tier
	cacheStep = "cache:" // a recorded model reply or discovery seed, by the digest of its key
)

// resumedRun is what a resumed run had finished before this session.
type resumedRun struct {
	steps    []string        // in order, as the run state lists them
	finished map[string]bool // the same steps, for lookup
	spent    time.Duration   // scan time the run had spent (budget.max_seconds)
}

func newResumedRun(sum state.Summary) resumedRun {
	finished := make(map[string]bool, len(sum.Steps))
	for _, step := range sum.Steps {
		finished[step] = true
	}
	return resumedRun{steps: sum.Steps, finished: finished, spent: sum.Elapsed}
}

// step returns the value of the first finished step with prefix.
func (r resumedRun) step(prefix string) (string, bool) {
	for _, step := range r.steps {
		if v, ok := strings.CutPrefix(step, prefix); ok {
			return v, true
		}
	}
	return "", false
}

// resumeRefusal is a resume refused because the run and this invocation
// differ; nothing was sent. It exits 2 (failureCode).
type resumeRefusal struct {
	field string // what differs, named for the user
}

func (r *resumeRefusal) Error() string {
	return fmt.Sprintf("the %s differs from the original run; nothing was sent; resume with the original settings or start a new run with creep scan", r.field)
}

func (r *resumeRefusal) ExitCode() int { return exitcode.ConfigError }

// refusalPrefix names the command an error comes from: resume for a
// refusal, scan for anything else.
func refusalPrefix(err error) string {
	var r *resumeRefusal
	if errors.As(err, &r) {
		return "creep resume"
	}
	return "creep scan"
}

// cacheStepID names the run-state cache entry k as a step: the digest of
// its key, so the step says which recording without holding any text.
func cacheStepID(k state.Key) string {
	h := sha256.New()
	for _, part := range []string{k.ContentHash, k.Model, k.PromptVersion} {
		h.Write([]byte(part + "\x00"))
	}
	return cacheStep + hex.EncodeToString(h.Sum(nil))
}

// respond puts the run-state cache in front of every model call and the
// discovery seed. A step the resumed run already finished is served from
// its recording only and never sent again; anything else follows the
// run's mode and, once answered, is recorded as finished. Only steps
// finished before this session are replay-only, so a planted cache file
// cannot stop a new scan (state.Store.Respond).
func (s *session) respond(k state.Key, call func() ([]byte, error)) ([]byte, error) {
	step := cacheStepID(k)
	if s.resumed.finished[step] {
		b, err := s.store.Respond(state.ModeReplay, k, call)
		if err != nil {
			return nil, fmt.Errorf("resume: the recording of a finished step: %w", err)
		}
		return b, nil
	}
	b, err := s.store.Respond(s.mode(), k, call)
	if err != nil {
		return nil, err
	}
	if err := s.record(step); err != nil {
		return nil, err
	}
	return b, nil
}

// record marks step finished, with the scan time spent so far.
func (s *session) record(step string) error {
	if err := s.run.StepDoneAt(step, s.elapsed()); err != nil {
		return fmt.Errorf("run state: %w", err)
	}
	return nil
}

// elapsed is the scan time the run has spent: what a resumed run had
// spent, plus this session's time since the deadline phase began.
func (s *session) elapsed() time.Duration {
	if s.scanStart.IsZero() {
		return s.resumed.spent
	}
	return s.resumed.spent + s.deps.sandbox.clock().Sub(s.scanStart)
}

// timeLeft is budget.max_seconds less what a resumed run already spent:
// resuming cannot reset the deadline. It may be zero or negative, and the
// deadline then fires at once.
func (s *session) timeLeft() time.Duration {
	return time.Duration(s.cfg.Budget.MaxSeconds)*time.Second - s.resumed.spent
}

// stepFiles records the digest of the walked files, or refuses a resumed
// run whose files changed since it recorded theirs.
func (s *session) stepFiles(files repoFiles) error {
	digest := filesDigest(readRepoFile(s.repo), files)
	if recorded, ok := s.resumed.step(filesStep); ok && recorded != digest {
		return &resumeRefusal{field: "file list or a file's content"}
	}
	return s.record(filesStep + digest)
}

// filesDigest hashes the walked paths, what the scan can read of each
// (the whole file, or only the head of one over the size cap, exactly as
// discovery reads it) and the walk's gaps.
func filesDigest(read func(string) ([]byte, error), files repoFiles) string {
	h := sha256.New()
	for _, path := range files.paths {
		data, err := read(path)
		status := "ok"
		switch {
		case errors.Is(err, errFileTooLarge):
			status = "too_large"
		case err != nil:
			status, data = "unreadable", nil
		}
		fmt.Fprintf(h, "%q %s %d\n", path, status, len(data))
		h.Write(data)
	}
	for _, g := range files.gaps {
		fmt.Fprintf(h, "gap %q %s\n", g.Path, g.Reason)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// resumedCalibration reads, from the cache only, the calibration of a
// resumed run that already calibrated, and refuses a changed or expired
// one: measuring again would send calls the run never made and could
// change the tier its plan was built for.
func (s *session) resumedCalibration(ctx context.Context, tier string) (calibrate.Calibration, error) {
	defer s.stats.start(phaseCalibrate)()
	cal, err := s.deps.calibrate(ctx, calibrate.CacheOptions{
		Options:   calibrate.Options{Seed: calibrationSeed, Model: s.model, Redactor: s.red},
		MaxAge:    time.Duration(s.cfg.Calibration.CacheDays) * 24 * time.Hour,
		CacheOnly: true,
	})
	switch {
	case errors.Is(err, calibrate.ErrNotCached):
		return cal, &resumeRefusal{field: "calibration (it is no longer cached)"}
	case err != nil:
		return cal, err
	case string(cal.Tier) != tier:
		return cal, &resumeRefusal{field: "calibrated tier"}
	}
	return cal, nil
}
