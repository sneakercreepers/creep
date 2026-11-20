package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/sandbox"
)

// appBuilder is what a scan uses of a *sandbox.Sandbox: one offline build
// of the app, then cleanup. sandboxDeps.open makes one; tests replace it.
type appBuilder interface {
	Build(ctx context.Context, repo sandbox.Repo) (sandbox.App, error)
	Close() error
}

// openSandbox is the production sandboxDeps.open.
func openSandbox(st sandbox.Status, runID string) (appBuilder, error) {
	s, err := sandbox.Open(st, runID)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Reasons verification is unavailable that the sandbox's build does not
// name (sandbox.BuildReason names the rest). Each is an ID for the report.
const (
	verifyNotChecked   = "not_checked"   // no runtime detector is wired (tests)
	verifyNoRuntime    = "no_runtime"    // no usable docker or podman
	verifySandboxError = "sandbox_error" // the sandbox did not open, or the run was aborted
	verifyInterrupted  = "interrupted"   // Ctrl+C stopped the build
	verifyDeadline     = reasonDeadline  // the scan deadline passed before or during the build
)

// buildFileBytes bounds one repository file copied into the build
// context; a larger one leaves the app unbuilt (context_refused).
const buildFileBytes = 64 << 20

// verifyApp builds the app in the sandbox when sandbox.enabled is set and a
// runtime is usable, and says what verification the findings got. It never
// fails the scan or changes its exit code: every way the build can stop is
// a closed reason in the report, findings stay probable, and the sandbox is
// closed on every path. The build ends by the scan deadline.
func (s *session) verifyApp(ctx context.Context, w io.Writer, files repoFiles, deadline time.Time) report.Verification {
	if !s.cfg.Sandbox.Enabled {
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
	case !time.Now().Before(deadline):
		return unavailableVerification(verifyDeadline, "")
	}
	return s.buildApp(ctx, w, best, files, deadline)
}

// buildApp opens a sandbox on the runtime, builds the app from the scan's
// files and closes the sandbox, whatever happened.
func (s *session) buildApp(ctx context.Context, w io.Writer, best sandbox.Status, files repoFiles, deadline time.Time) report.Verification {
	fmt.Fprintf(w, "sandbox: building the app offline with %s (isolation %s)\n", best.Runtime, best.Isolation)
	box, err := s.deps.sandbox.open(best, s.run.ID())
	if err != nil {
		printError(w, "sandbox", err)
		return unavailableVerification(verifySandboxError, "open")
	}
	defer closeSandbox(w, box)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	app, err := box.Build(ctx, sandbox.Repo{Paths: files.paths, Read: buildReader(s.repo)})
	return appVerification(ctx, app, err)
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
	case errors.Is(err, sandbox.ErrInterrupted):
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
// says: a reason or detail that is not an ID never fails the scan.
func unavailableVerification(reason, detail string) report.Verification {
	if !report.ValidID(reason) {
		reason, detail = verifySandboxError, "reason"
	}
	if !report.ValidID(detail) {
		detail = ""
	}
	return report.Verification{Status: report.VerificationUnavailable, Reason: reason, Detail: detail}
}

// closeSandbox removes the run's containers, built images and network. A
// failure is reported, not fatal: creep clean removes what is left.
func closeSandbox(w io.Writer, box appBuilder) {
	if err := box.Close(); err != nil {
		printError(w, "sandbox: cleanup failed (run creep clean)", err)
	}
}
