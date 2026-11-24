package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/state"
)

// stateDir is the run-state directory, relative to the scanned project.
const stateDir = ".creep"

// runResume continues an interrupted scan (#335, ADR 0032). It refuses,
// with nothing sent, a run that is locked, tampered, truncated, foreign,
// ended or started with other settings; otherwise it runs the scan's
// pipeline on the same run, where every step the run finished is served
// from its recording and the rest is sent as a scan would send it, under
// what is left of the run's budget and deadline.
func runResume(e env, args []string) int {
	if len(args) != 1 {
		printError(e.stderr, "creep resume", fmt.Errorf("want exactly one run ID, got %d arguments", len(args)))
		return exitcode.ConfigError
	}
	sum, err := loadResumable(args[0])
	if err == nil {
		e.opts, err = resumeOptions(e.opts, sum)
	}
	if err != nil {
		printError(e.stderr, "creep resume", err)
		return exitcode.ConfigError
	}
	in, err := loadScanInputs(e, nil)
	if err != nil {
		printError(e.stderr, "creep resume", err)
		return exitcode.ConfigError
	}
	ctx, cancel := context.WithCancelCause(e.parent())
	defer cancel(nil)
	s, err := openSession(ctx, e, in, func(s *session) error { return s.reopenRun(sum.ID) })
	if err != nil {
		printError(e.stderr, "creep resume", err)
		return exitcode.ConfigError
	}
	defer s.close()
	fmt.Fprintf(e.stderr, "creep resume: run %s: %d finished steps are served from .creep; what did not finish is sent again\n",
		sum.ID, len(s.resumed.steps))
	return s.runPipeline(ctx, cancel, e)
}

// resumeOptions takes the run's state mode (live, --record or --replay)
// from the run, refusing an explicit flag that says otherwise, and refuses
// a run with no header before any config is read.
func resumeOptions(opts globalOptions, sum state.Summary) (globalOptions, error) {
	if sum.Header == nil {
		return opts, errNoHeader
	}
	if (opts.record && sum.Mode != state.ModeRecord) || (opts.replay && sum.Mode != state.ModeReplay) {
		return opts, &resumeRefusal{field: "state mode (--record or --replay)"}
	}
	opts.record, opts.replay = sum.Mode == state.ModeRecord, sum.Mode == state.ModeReplay
	return opts, nil
}

// reopenRun is openState for resume: it reopens the run under the state
// lock, so the checks loadResumable made hold for the run it continues,
// and refuses it unless this invocation's settings match its header.
func (s *session) reopenRun(id string) error {
	var err error
	if s.store, err = state.OpenUser(stateDir); err != nil {
		return err
	}
	if s.run, err = s.store.Resume(id); err != nil {
		return err
	}
	sum := s.run.Summary()
	if sum.Mode != s.mode() {
		return &resumeRefusal{field: "state mode (--record or --replay)"}
	}
	if err := compareHeader(sum.Header, s.header()); err != nil {
		return err
	}
	if s.boxID, err = resumedBoxID(id); err != nil {
		return err
	}
	s.resumed = newResumedRun(sum)
	s.staleReports = removeReports(s.store.Root())
	return nil
}

// resumedBoxID names a resumed run's sandbox apart from the interrupted
// run's, so a container, network or image it left behind is never reused:
// the app is built again (creep clean removes the leftovers).
func resumedBoxID(id string) (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sandbox name: %w", err)
	}
	return id + "-resume-" + hex.EncodeToString(b), nil
}

// loadResumable reopens the run under the state lock, so a scan still
// writing to it fails the resume (state.ErrLocked) instead of reading a log
// mid-append, and refuses a run that already ended. It appends nothing and
// never creates the state directory: resuming in the wrong folder must not
// leave one behind.
func loadResumable(id string) (state.Summary, error) {
	if _, err := os.Lstat(stateDir); err != nil {
		return state.Summary{}, fmt.Errorf("no run state in this directory: %w", err)
	}
	store, err := state.OpenUser(stateDir)
	if err != nil {
		return state.Summary{}, err
	}
	defer store.Close()
	run, err := store.Resume(id)
	if err != nil {
		return state.Summary{}, err
	}
	defer run.Close()
	return run.Summary(), nil
}
