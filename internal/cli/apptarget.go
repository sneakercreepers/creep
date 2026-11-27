package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/sandbox"
	"github.com/sneakercreepers/creep/internal/verify"
)

// appTarget is a started app and what its runs used, for the bundle.
type appTarget struct {
	target verify.Target
	images verify.Images
	seed   verify.Seed
}

// startTarget makes the built app reachable for PoCs: its declared port,
// the run's database, empty, then the app's own migrate step against it
// (#364), then the app on the run network. A database that does not come
// up is no database (a marker PoC is then no_database), and a migrate
// step that fails leaves the database as the step left it; neither is a
// failure. Anything else that stops it is a closed verification reason,
// as for the build.
func startTarget(ctx context.Context, w io.Writer, box appSandbox, app sandbox.App) (appTarget, *report.Verification) {
	port, err := box.AppPort(ctx, app)
	switch {
	case err != nil:
		return appTarget{}, stopped(ctx, unavailableVerification(verifySandboxError, "port"))
	case port == 0:
		return appTarget{}, stopped(ctx, unavailableVerification(verifyNoPort, ""))
	}
	t := appTarget{target: verify.Target{Port: port}, images: verify.Images{App: app.Image, Runner: sandbox.RunnerImage}}
	if t.startDatabase(ctx, w, box) {
		t.migrate(ctx, w, box, app)
	}
	if err := box.StartApp(ctx, app); err != nil {
		printError(w, "sandbox: the app did not start", err)
		return appTarget{}, stopped(ctx, unavailableVerification(verifyStartFailed, "app"))
	}
	return t, nil
}

// startDatabase reports whether the run's database came up.
func (t *appTarget) startDatabase(ctx context.Context, w io.Writer, box appSandbox) bool {
	if _, err := box.StartDatabase(ctx); err != nil {
		printError(w, "sandbox: the database did not start; marker PoCs get no_database", err)
		return false
	}
	t.target.Database = true
	t.images.Database = sandbox.DatabaseImage
	return true
}

// migrate runs the app's migrate step and records it as the seed.
func (t *appTarget) migrate(ctx context.Context, w io.Writer, box appSandbox, app sandbox.App) {
	t.seed = verify.Seed{Migrations: []string{}, SHA256: verify.SeedDigest(app.MigrateCommand())}
	if skip := app.MigrateSkipped(); skip != "" {
		// A closed reason, never repository text.
		_, _ = fmt.Fprintf(w, "sandbox: the compose file's migrate step was skipped (%s); the app must set up its own schema\n", skip)
		return
	}
	if err := box.Migrate(ctx, app); err != nil {
		printError(w, "sandbox: the app's migrate step failed; PoCs run against the database it left", err)
	}
}

// stopped names Ctrl+C or the deadline when either ended ctx, as for the
// build, so a cut run is never read as a broken app.
func stopped(ctx context.Context, v report.Verification) *report.Verification {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		v = unavailableVerification(verifyInterrupted, "")
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		v = unavailableVerification(verifyDeadline, "")
	}
	return &v
}
