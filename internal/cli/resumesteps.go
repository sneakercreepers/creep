package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/state"
)

// resumeState is a session's resume bookkeeping (#335). For a new scan
// finished is empty, so nothing is owed or served from a recording.
type resumeState struct {
	finished state.Finished
	// owed are the finished cache steps (by key digest) not served yet:
	// while any is left, nothing new is sent (session.respond).
	owed map[string]bool
	// scanStart is when the deadline phase began; zero before it.
	scanStart time.Time
	// hashing is what the files digest took, counted against the deadline.
	hashing time.Duration
	// refused is a resume refusal found mid-pipeline (session.refuse), and
	// cancel the run context's cancel it stops the run with.
	refused *resumeRefusal
	cancel  context.CancelCauseFunc
}

func newResumeState(sum state.Summary) resumeState {
	f := state.NewFinished(sum)
	return resumeState{finished: f, owed: f.Owed()}
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

func (r *resumeRefusal) ExitCode() int { return exitcode.ConfigError }

// errRecordingGone refuses a resume whose finished step cannot be served
// with the reply the run got.
var errRecordingGone = &resumeRefusal{why: "the recording of a finished step is missing from .creep/cache or was rewritten by a later scan; no call the run had not sent was sent; start a new run with creep scan"}

// errOutOfOrder refuses a resume that asks for a step the run had not
// reached while a finished step is still unserved (v0.4 review A1): the
// run would mix a new reply into what it had finished, for example after a
// file changed between the files digest and discovery's read of it.
var errOutOfOrder = &resumeRefusal{why: "the resumed run asked for a step out of order, before every finished step was served; nothing new was sent; start a new run with creep scan"}

// refusalPrefix names the command an error comes from: resume for a
// refusal, scan for anything else.
func refusalPrefix(err error) string {
	var r *resumeRefusal
	if errors.As(err, &r) {
		return "creep resume"
	}
	return "creep scan"
}

// respond puts the run-state cache in front of every model call and the
// discovery seed. A step the resumed run already finished is served from
// its recording only, never sent again, and only when the recording is
// the reply the run got; otherwise the resume is refused. Any other step
// is refused while a finished step is still owed, since the pipeline asks
// for them first: calls are sequential, so a send that comes early means
// the run changed. Once nothing is owed, a step follows the run's mode
// and, once answered, is recorded with its reply's digest. Only steps
// finished before this session are replay-only, so a planted cache file
// cannot stop a new scan (state.Store.Respond).
func (s *session) respond(k state.Key, call func() ([]byte, error)) ([]byte, error) {
	if s.resume.refused != nil {
		return nil, s.resume.refused // the run is refused: nothing more is served or sent
	}
	if s.resume.finished.IsFinished(k) {
		b, err := s.store.Respond(state.ModeReplay, k, call)
		if err != nil || !s.resume.finished.Matches(k, b) {
			return nil, s.refuse(errRecordingGone)
		}
		delete(s.resume.owed, k.Digest())
		return b, nil
	}
	if len(s.resume.owed) > 0 {
		return nil, s.refuse(errOutOfOrder)
	}
	b, err := s.store.Respond(s.mode(), k, call)
	if err != nil {
		return nil, err
	}
	if err := s.record(state.CacheStep(k, b)); err != nil {
		return nil, err
	}
	return b, nil
}

// refuse stops the run on a refusal found mid-pipeline: it cancels the
// run's context, so no stage sends anything more, and runPipeline exits 2
// without an end line instead of reporting.
func (s *session) refuse(r *resumeRefusal) error {
	if s.resume.refused == nil {
		s.resume.refused = r
		if s.resume.cancel != nil {
			s.resume.cancel(r)
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
// spent, plus this session's files digest and its time since the deadline
// phase began.
func (s *session) elapsed() time.Duration {
	spent := s.resume.finished.Spent() + s.resume.hashing
	if s.resume.scanStart.IsZero() {
		return spent
	}
	return spent + s.deps.sandbox.clock().Sub(s.resume.scanStart)
}

// timeLeft is budget.max_seconds less what the run already spent, a
// resumed run's earlier sessions and this one's files digest: resuming
// cannot reset the deadline. It may be zero or negative, and the deadline
// then fires at once.
func (s *session) timeLeft() time.Duration {
	return time.Duration(s.cfg.Budget.MaxSeconds)*time.Second - s.resume.finished.Spent() - s.resume.hashing
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
