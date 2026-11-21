package cli

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/sandbox"
	"github.com/sneakercreepers/creep/internal/verify"
)

// migrationBytes bounds one migration read for the run's database; the
// sandbox refuses a larger one anyway.
const migrationBytes = 1 << 20

// appTarget is a started app and what its runs used, for the bundle.
type appTarget struct {
	target verify.Target
	images verify.Images
	seed   verify.Seed
}

// startTarget makes the built app reachable for PoCs: its declared port,
// the run's database when the repository has migrations, then the app on
// the run network. A database that does not come up is no database (a
// marker PoC is then no_database), never a failure. Anything else that
// stops it is a closed verification reason, as for the build.
func startTarget(ctx context.Context, w io.Writer, box appSandbox, app sandbox.App, repo *os.Root, paths []string) (appTarget, *report.Verification) {
	port, err := box.AppPort(ctx, app)
	switch {
	case err != nil:
		return appTarget{}, stopped(ctx, unavailableVerification(verifySandboxError, "port"))
	case port == 0:
		return appTarget{}, stopped(ctx, unavailableVerification(verifyNoPort, ""))
	}
	t := appTarget{target: verify.Target{Port: port}, images: verify.Images{App: app.Image, Runner: sandbox.RunnerImage}}
	if migrations := readMigrations(repo, paths); len(migrations) > 0 {
		t.startDatabase(ctx, w, box, migrations)
	}
	if err := box.StartApp(ctx, app); err != nil {
		printError(w, "sandbox: the app did not start", err)
		return appTarget{}, stopped(ctx, unavailableVerification(verifyStartFailed, "app"))
	}
	return t, nil
}

func (t *appTarget) startDatabase(ctx context.Context, w io.Writer, box appSandbox, migrations []sandbox.Migration) {
	if _, err := box.StartDatabase(ctx, migrations); err != nil {
		printError(w, "sandbox: the database did not start; marker PoCs get no_database", err)
		return
	}
	t.target.Database = true
	t.images.Database = sandbox.DatabaseImage
	t.seed = verify.Seed{SHA256: verify.SeedDigest(migrations)}
	for _, m := range migrations {
		t.seed.Migrations = append(t.seed.Migrations, m.Path)
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

// readMigrations reads the repository's migrations, in order, through the
// scan's confined reader. Any that cannot be read leaves the database out:
// a partial seed is not the app's schema.
func readMigrations(repo *os.Root, paths []string) []sandbox.Migration {
	names, err := sandbox.MigrationPaths(paths)
	if err != nil || len(names) == 0 {
		return nil
	}
	out := make([]sandbox.Migration, 0, len(names))
	for _, name := range names {
		data, err := readInRoot(repo, name, migrationBytes)
		if err != nil {
			return nil
		}
		out = append(out, sandbox.Migration{Path: name, SQL: data})
	}
	return out
}
