package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"
)

// Labels on every container creep starts. LabelManaged marks creep's
// containers for creep clean; LabelRun ties one to its run.
const (
	LabelManaged = "io.github.sneakercreepers.creep.managed"
	LabelRun     = "io.github.sneakercreepers.creep.run"
)

// cleanupTimeout bounds removing containers after a run, a timeout or an
// interrupt.
const cleanupTimeout = 30 * time.Second

// Errors a Run returns besides spec and start failures.
var (
	ErrUnusable    = errors.New("sandbox runtime not usable")
	ErrTimeout     = errors.New("sandbox container timed out")
	ErrInterrupted = errors.New("sandbox run interrupted")
	ErrStart       = errors.New("sandbox container did not start")
)

var runIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Result is one finished container: its exit code and at most 1 MiB of
// its stdout.
type Result struct {
	ExitCode  int
	Output    []byte
	Truncated bool
}

// Sandbox starts containers for one run, all with the hardened profile.
type Sandbox struct {
	status   Status
	runID    string
	run      runFunc
	work     string // temporary directory for mounted files, 0700
	workReal string // work with links resolved, for mount checks
	seq      atomic.Uint64
	notify   func(chan<- os.Signal) // signal.Notify for os.Interrupt; tests replace it
	stop     func(chan<- os.Signal)
}

// Open prepares a sandbox for runID on a usable runtime from Detect.
func Open(st Status, runID string) (*Sandbox, error) {
	if !st.Usable() || st.Path == "" {
		return nil, fmt.Errorf("open sandbox on %s (%s): %w", st.Runtime, st.Reason, ErrUnusable)
	}
	return newSandbox(st, runID, newExecRunner(st.Path, st.env))
}

func newSandbox(st Status, runID string, run runFunc) (*Sandbox, error) {
	if !runIDPattern.MatchString(runID) {
		return nil, fmt.Errorf("open sandbox: run ID %q: %w", runID, ErrSpec)
	}
	work, err := os.MkdirTemp("", "creep-sandbox-")
	if err != nil {
		return nil, fmt.Errorf("open sandbox: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(work)
	if err != nil {
		_ = os.RemoveAll(work)
		return nil, fmt.Errorf("open sandbox: %w", err)
	}
	return &Sandbox{
		status: st, runID: runID, run: run, work: work, workReal: resolved,
		notify: func(c chan<- os.Signal) { signal.Notify(c, os.Interrupt) },
		stop:   func(c chan<- os.Signal) { signal.Stop(c) },
	}, nil
}

// global is the flags before the subcommand: Docker's pinned endpoint.
func (s *Sandbox) global() []string { return globalArgs(s.status) }

func globalArgs(st Status) []string {
	if st.Runtime == Docker && st.Host != "" {
		return []string{"--host=" + st.Host}
	}
	return []string{}
}

// Run starts one container and waits for it. On timeout or Ctrl+C the
// container is removed and Run returns ErrTimeout or ErrInterrupted; the
// caller should then stop the run.
func (s *Sandbox) Run(ctx context.Context, spec Spec) (Result, error) {
	name := "creep-" + s.runID + "-" + strconv.FormatUint(s.seq.Add(1), 10)
	args, err := s.runArgs(name, spec)
	if err != nil {
		return Result{}, err
	}
	ctx, done := s.interruptible(ctx)
	defer done()
	runCtx, cancel := context.WithTimeout(ctx, timeoutOf(spec))
	defer cancel()
	res, err := s.run(runCtx, args, outputLimit)
	if err != nil || res.exit == 125 {
		// The CLI is gone or the runtime refused; the container may still exist.
		s.remove(name)
		return Result{}, runError(ctx, runCtx, err)
	}
	return Result{ExitCode: res.exit, Output: res.stdout, Truncated: res.truncated}, nil
}

// runError names why a run ended without a result.
func runError(ctx, runCtx context.Context, err error) error {
	switch {
	case errors.Is(context.Cause(ctx), ErrInterrupted):
		return ErrInterrupted
	case ctx.Err() != nil:
		return fmt.Errorf("sandbox run: %w", ctx.Err())
	case runCtx.Err() != nil:
		return ErrTimeout
	case err != nil:
		return fmt.Errorf("sandbox run: %w: %w", ErrStart, err)
	}
	return ErrStart // exit 125: the runtime could not create or start it
}

// interruptible cancels ctx with ErrInterrupted on Ctrl+C while a
// container runs, so the container is removed instead of left behind.
func (s *Sandbox) interruptible(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	sig := make(chan os.Signal, 1)
	s.notify(sig)
	finished := make(chan struct{})
	go func() {
		select {
		case <-sig:
			cancel(ErrInterrupted)
		case <-finished:
		}
	}()
	return ctx, func() { s.stop(sig); close(finished); cancel(nil) }
}

// remove force-removes one container, ignoring "no such container".
func (s *Sandbox) remove(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	_, _ = s.run(ctx, append(s.global(), "rm", "--force", name), infoLimit)
}

// Close removes every container of this run and the work directory. It is
// safe to call more than once.
func (s *Sandbox) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	_, err := removeLabeled(ctx, s.run, s.status, LabelRun+"="+s.runID)
	if rmErr := os.RemoveAll(s.work); rmErr != nil {
		err = errors.Join(err, fmt.Errorf("remove sandbox work directory: %w", rmErr))
	}
	return err
}
