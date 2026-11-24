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
	// cacheStep is a recorded model reply or discovery seed:
	// cache:<key digest>:<reply digest>, so a resume serves only the exact
	// reply this run got, never one a later scan recorded under the key.
	cacheStep = "cache:"
)

// digestHex is the length of each digest in a cache step: 128 bits each,
// so the step fits the state's 128-character ID.
const digestHex = 32

// resumedRun is what a resumed run had finished before this session.
type resumedRun struct {
	steps   []string          // in order, as the run state lists them
	replies map[string]string // cache key digest -> digest of the reply the run got
	spent   time.Duration     // scan time the run had spent (budget.max_seconds)
}

func newResumedRun(sum state.Summary) resumedRun {
	replies := map[string]string{}
	for _, step := range sum.Steps {
		if key, reply, ok := strings.Cut(strings.TrimPrefix(step, cacheStep), ":"); ok && strings.HasPrefix(step, cacheStep) {
			replies[key] = reply // the cache holds the last reply recorded under key
		}
	}
	return resumedRun{steps: sum.Steps, replies: replies, spent: sum.Elapsed}
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
	why   string // the whole message instead, when set
}

func (r *resumeRefusal) Error() string {
	if r.why != "" {
		return r.why
	}
	return fmt.Sprintf("the %s differs from the original run; nothing was sent; resume with the original settings or start a new run with creep scan", r.field)
}

// errRecordingGone refuses a resume whose finished step cannot be served
// with the reply the run got. The pipeline asks for every finished step
// before any step the run had not reached, so no new call was sent.
var errRecordingGone = &resumeRefusal{why: "the recording of a finished step is missing from .creep/cache or was rewritten by a later scan; no call the run had not sent was sent; start a new run with creep scan"}

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

// keyDigest names the run-state cache entry k without holding any text.
func keyDigest(k state.Key) string {
	h := sha256.New()
	for _, part := range []string{k.ContentHash, k.Model, k.PromptVersion} {
		h.Write([]byte(part + "\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))[:digestHex]
}

func replyDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:digestHex]
}

// respond puts the run-state cache in front of every model call and the
// discovery seed. A step the resumed run already finished is served from
// its recording only, never sent again, and only when the recording is
// the reply the run got; otherwise the resume is refused (refuse). Any
// other step follows the run's mode and, once answered, is recorded with
// its reply's digest. Only steps finished before this session are
// replay-only, so a planted cache file cannot stop a new scan
// (state.Store.Respond).
func (s *session) respond(k state.Key, call func() ([]byte, error)) ([]byte, error) {
	if s.refused != nil {
		return nil, s.refused // the run is refused: nothing more is served or sent
	}
	key := keyDigest(k)
	if want, ok := s.resumed.replies[key]; ok {
		b, err := s.store.Respond(state.ModeReplay, k, call)
		if err != nil || replyDigest(b) != want {
			return nil, s.refuse(errRecordingGone)
		}
		return b, nil
	}
	b, err := s.store.Respond(s.mode(), k, call)
	if err != nil {
		return nil, err
	}
	if err := s.record(cacheStep + key + ":" + replyDigest(b)); err != nil {
		return nil, err
	}
	return b, nil
}

// refuse stops the run on a refusal found mid-pipeline: it cancels the
// run's context, so no stage sends anything more, and runPipeline exits 2
// without an end line instead of reporting.
func (s *session) refuse(r *resumeRefusal) error {
	if s.refused == nil {
		s.refused = r
		if s.cancel != nil {
			s.cancel(r)
		}
	}
	return r
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
