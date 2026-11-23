package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/sandbox"
	"github.com/sneakercreepers/creep/internal/verify"
)

// appSandbox is what a scan and creep reproduce use of a *sandbox.Sandbox:
// one offline build of the app, its port, the database and the app on the
// run network, the PoC runner (verify.Runner), then cleanup.
// sandboxDeps.open makes one; tests replace it.
type appSandbox interface {
	Build(ctx context.Context, repo sandbox.Repo) (sandbox.App, error)
	AppPort(ctx context.Context, app sandbox.App) (int, error)
	StartDatabase(ctx context.Context, migrations []sandbox.Migration) (sandbox.Database, error)
	StartApp(ctx context.Context, app sandbox.App) error
	verify.Runner
	Close() error
}

// interruptible is ctx canceled by Ctrl+C until stop; tests replace the
// hook (sandboxDeps.interrupt).
func (d sandboxDeps) interruptible(ctx context.Context) (context.Context, context.CancelFunc) {
	if d.interrupt == nil {
		return signal.NotifyContext(ctx, os.Interrupt)
	}
	return d.interrupt(ctx)
}

// clock is the time the build checks the scan deadline against.
func (d sandboxDeps) clock() time.Time {
	if d.now == nil {
		return time.Now()
	}
	return d.now()
}

// openSandbox is the production sandboxDeps.open. The mirror comes from
// the operator's config only (the project file cannot set it, ADR 0029).
func openSandbox(st sandbox.Status, runID string, mirror sandbox.Mirror) (appSandbox, error) {
	s, err := sandbox.Open(st, runID)
	if err != nil {
		return nil, err
	}
	s.UseMirror(mirror)
	return s, nil
}

// buildMirror is the sandbox's view of sandbox.mirror.
func buildMirror(cfg config.Sandbox) sandbox.Mirror {
	return sandbox.Mirror{Bridge: cfg.Mirror.Bridge, Proxy: cfg.Mirror.Proxy}
}

// buildHow says how the build reaches packages, for the scan's stderr.
func buildHow(m sandbox.Mirror) string {
	if m.Set() {
		return "through the operator's mirror (sandbox.mirror)"
	}
	return "offline"
}

// Reasons verification is unavailable that the sandbox's build does not
// name (sandbox.BuildReason names the rest). Each is an ID for the report.
const (
	verifyNotChecked   = "not_checked"   // no runtime detector is wired (tests)
	verifyNoRuntime    = "no_runtime"    // no usable docker or podman
	verifySandboxError = "sandbox_error" // the sandbox did not open, or the run was aborted
	verifyInterrupted  = "interrupted"   // Ctrl+C stopped the build
	verifyDeadline     = reasonDeadline  // the scan deadline passed before or during the build
	verifyNoPort       = "no_port"       // the built image declares no TCP port (EXPOSE)
	verifyStartFailed  = "start_failed"  // the app did not start on the run network
)

// buildFileBytes bounds one repository file copied into the build
// context; a larger one leaves the app unbuilt (context_refused).
const buildFileBytes = 64 << 20

// verifyApp builds the app in the sandbox when sandbox.enabled is set, the
// scan is nightly (a pr scan never builds, #28) and a runtime is usable,
// runs a PoC for each probable finding it can (#25)
// and says what verification the findings got. It never fails the scan or
// makes it incomplete: every way the build or a PoC can stop is a closed
// reason or a count in the report, such findings stay probable, and the
// sandbox is closed on every path. Only a PoC that verified moves a
// finding, to verified, which changes the exit code only as the gate
// reads verified (ADR 0009). The build and the PoCs end by the scan
// deadline.
func (s *session) verifyApp(ctx context.Context, w io.Writer, files repoFiles, deadline time.Time, in pocInput) report.Verification {
	if !s.cfg.Sandbox.Enabled || !s.gate.verifies(w) {
		return report.Verification{}
	}
	rep, checked := detectSandbox(ctx, s.deps.sandbox, s.cfg.Sandbox)
	best, ok := rep.Best()
	switch {
	case !checked:
		return unavailableVerification(verifyNotChecked, "")
	case !ok:
		return unavailableVerification(verifyNoRuntime, "")
	case s.deps.sandbox.open == nil:
		return unavailableVerification(verifyNotChecked, "")
	case !s.deps.sandbox.clock().Before(deadline):
		return unavailableVerification(verifyDeadline, "")
	}
	return s.buildApp(ctx, w, best, files, deadline, in)
}

// buildApp opens a sandbox on the runtime, builds the app from the scan's
// files and closes the sandbox, whatever happened.
//
// From before the sandbox opens until it is closed, Ctrl+C cancels the
// build instead of killing creep, so Close always runs: the work
// directory, which holds a copy of the repository, and any built image
// never outlive the scan. The build's time is what the scan deadline
// leaves, read from the sandbox clock.
func (s *session) buildApp(ctx context.Context, w io.Writer, best sandbox.Status, files repoFiles, deadline time.Time, in pocInput) report.Verification {
	ctx, stop := s.deps.sandbox.interruptible(ctx)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, deadline.Sub(s.deps.sandbox.clock()))
	defer cancel()
	mirror := buildMirror(s.cfg.Sandbox)
	fmt.Fprintf(w, "sandbox: building the app %s with %s (isolation %s)\n", buildHow(mirror), best.Runtime, best.Isolation)
	box, err := s.deps.sandbox.open(best, s.run.ID(), mirror)
	if err != nil {
		printError(w, "sandbox", err)
		return unavailableVerification(verifySandboxError, "open")
	}
	defer closeSandbox(w, box)
	app, err := box.Build(ctx, sandbox.Repo{Paths: files.paths, Read: buildReader(s.repo)})
	if v := appVerification(ctx, app, err); v.Status != report.VerificationAppBuilt {
		return v
	}
	return s.runPoCs(ctx, w, box, app, files.paths, in)
}

// buildReader is the scan's own reader for the build context (TB1): it
// stays inside the repository root, opens only regular files without
// blocking, and caps each file.
func buildReader(root *os.Root) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) { return readInRoot(root, path, buildFileBytes) }
}

// appVerification turns Build's outcome into the report's.
func appVerification(ctx context.Context, app sandbox.App, err error) report.Verification {
	switch {
	case errors.Is(err, sandbox.ErrInterrupted), err != nil && errors.Is(ctx.Err(), context.Canceled):
		return unavailableVerification(verifyInterrupted, "")
	case err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		return unavailableVerification(verifyDeadline, "")
	case err != nil:
		return unavailableVerification(verifySandboxError, "build")
	case !app.Built():
		return unavailableVerification(string(app.Unavailable), app.Detail)
	}
	return report.Verification{Status: report.VerificationAppBuilt}
}

// unavailableVerification keeps the report valid whatever the sandbox
// says: a reason outside the report's closed set, or a detail that is not
// an ID, never fails the scan.
func unavailableVerification(reason, detail string) report.Verification {
	if !report.ValidVerificationReason(reason) {
		reason, detail = verifySandboxError, "reason"
	}
	if !report.ValidID(detail) {
		detail = ""
	}
	return report.Verification{Status: report.VerificationUnavailable, Reason: reason, Detail: detail}
}

// closeSandbox removes the run's containers, built images and network. A
// failure is reported, not fatal: creep clean removes what is left.
func closeSandbox(w io.Writer, box appSandbox) {
	if err := box.Close(); err != nil {
		printError(w, "sandbox: cleanup failed (run creep clean)", err)
	}
}
