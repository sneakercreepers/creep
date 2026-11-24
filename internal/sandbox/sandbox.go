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
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Labels on every container creep starts. LabelManaged marks creep's
// containers for creep clean; LabelRun ties one to its run.
const (
	LabelManaged   = "io.github.sneakercreepers.creep.managed"
	LabelRun       = "io.github.sneakercreepers.creep.run"
	LabelContainer = "io.github.sneakercreepers.creep.container" // the container's own name, so cleanup never acts on a name alone
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
	canaries atomic.Uint64
	notify   func(chan<- os.Signal) // signal.Notify for os.Interrupt; tests replace it
	stop     func(chan<- os.Signal)
	caught   func()                                       // called once Ctrl+C has canceled the context; tests wait on it
	netArgs  func(st Status, name, runID string) []string // networkArgs; tests replace it
	buildFor time.Duration                                // buildTimeout; tests shorten it

	mu         sync.Mutex
	network    string    // the run's network once created
	database   bool      // StartDatabase ran
	ready      *Database // the database StartDatabase seeded, once ready
	app        bool      // StartApp ran
	fileCanary string    // the content of the app's canary file, once planted
	images     []string  // image IDs Build made
	aborted    error     // why the run was aborted (a canary failure); sticky

	// mirror is the operator's build mirror, set once by Open and never
	// changed; the zero Mirror builds offline.
	mirror Mirror
}

// Open prepares a sandbox for runID on a usable runtime from Detect.
// Builds run on mirror's network instead of none when it is set (ADR
// 0029); Build checks it before each build and refuses the build
// (BuildMirrorRefused), never the scan, when it does not hold.
func Open(st Status, runID string, mirror Mirror) (*Sandbox, error) {
	if !st.Usable() || st.Path == "" {
		return nil, fmt.Errorf("open sandbox on %s (%s): %w", st.Runtime, st.Reason, ErrUnusable)
	}
	s, err := newSandbox(st, runID, nil)
	if err != nil {
		return nil, err
	}
	s.mirror = mirror
	config := filepath.Join(s.work, "docker-config")
	if err := os.Mkdir(config, 0o700); err != nil {
		_ = os.RemoveAll(s.work)
		return nil, fmt.Errorf("open sandbox: %w", err)
	}
	s.run = newExecRunner(st.Path, withEnv(st.env, "DOCKER_CONFIG", config))
	return s, nil
}

// withEnv replaces or adds one variable. The sandbox's CLI gets an empty
// DOCKER_CONFIG: the endpoint is pinned with --host, so it needs no
// context, and the operator's config.json would add its proxies, with any
// credentials, to every container.
func withEnv(env []string, name, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if !strings.HasPrefix(kv, name+"=") {
			out = append(out, kv)
		}
	}
	return append(out, name+"="+value)
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
		notify:  func(c chan<- os.Signal) { signal.Notify(c, os.Interrupt) },
		stop:    func(c chan<- os.Signal) { signal.Stop(c) },
		netArgs: networkArgs, buildFor: buildTimeout,
	}, nil
}

// global is the flags before the subcommand: Docker's pinned endpoint.
func (s *Sandbox) global() []string { return globalArgs(s.status) }

// globalArgs pins where the CLI connects: Docker's checked endpoint, and
// Podman's local engine even when its config asks for a remote one.
func globalArgs(st Status) []string {
	switch {
	case st.Runtime == Docker && st.Host != "":
		return []string{"--host=" + st.Host}
	case st.Runtime == Podman:
		return []string{"--remote=false"}
	}
	return []string{}
}

// Run starts one container with no network and waits for it. On timeout
// or Ctrl+C the container is removed and Run returns ErrTimeout or
// ErrInterrupted; the caller should then stop the run. After a canary
// failure it starts nothing (RunBatch).
func (s *Sandbox) Run(ctx context.Context, spec Spec) (Result, error) {
	if err := s.abortErr(); err != nil {
		return Result{}, err
	}
	spec.networked, spec.alias, spec.detach, spec.tmpfs = false, "", false, nil
	return s.start(ctx, spec)
}

// start runs one container as its spec says. A detached one (a service)
// returns once started and runs until Close.
func (s *Sandbox) start(ctx context.Context, spec Spec) (Result, error) {
	name := "creep-" + s.runID + "-" + strconv.FormatUint(s.seq.Add(1), 10)
	args, err := s.runArgs(name, spec)
	if err != nil {
		return Result{}, err
	}
	if err := s.checkImage(ctx, spec); err != nil {
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
			if s.caught != nil {
				s.caught()
			}
		case <-finished:
		}
	}()
	return ctx, func() { s.stop(sig); close(finished); cancel(nil) }
}

// remove force-removes one container, ignoring "no such container".
func (s *Sandbox) remove(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	// By label, never by name: a name conflict means another container,
	// which may not be creep's, already has the name.
	_, _ = removeLabeled(ctx, s.run, s.status, LabelRun+"="+s.runID, LabelContainer+"="+name)
}

// Close removes every container of this run, then the images it built and
// its network (both need the containers gone), then the work directory.
// It is safe to call more than once.
func (s *Sandbox) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	_, err := removeLabeled(ctx, s.run, s.status, LabelRun+"="+s.runID)
	if err == nil {
		known := s.builtImages()
		_, imgErr := removeImages(ctx, s.run, s.status, known, LabelRun+"="+s.runID)
		if imgErr == nil {
			s.forgetImages(known)
		}
		_, netErr := removeNetworks(ctx, s.run, s.status, LabelRun+"="+s.runID)
		err = errors.Join(imgErr, netErr)
	}
	if rmErr := os.RemoveAll(s.work); rmErr != nil {
		err = errors.Join(err, fmt.Errorf("remove sandbox work directory: %w", rmErr))
	}
	return err
}
