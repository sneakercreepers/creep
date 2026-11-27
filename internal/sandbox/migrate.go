package sandbox

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrMigrate marks an app's migrate step that exited non-zero.
var ErrMigrate = errors.New("app migrate step failed")

// migrateTimeout bounds the migrate step: longer than a PoC, since a
// framework's migrations can be many, and within MaxTimeout.
const migrateTimeout = 5 * time.Minute

// Migrate runs the app's migrate step, the command of its compose file's
// migrate service (composeMigrate), once and to its end: in the image
// Build made, in its working directory, on the run's internal network
// against the run's database, with the synthetic env (appEnv) and the
// hardened profile, after the canary. It is the only schema setup creep
// does, whatever the app's language: the database starts empty, and an
// app without a migrate step sets up its schema when it starts, or has
// none. The step is the repository's own code and runs only here, inside
// the sandbox, never on the host; its arguments follow the image, so the
// runtime never reads them as flags. Without a step it does nothing; it
// needs the run's database (StartDatabase).
func (s *Sandbox) Migrate(ctx context.Context, app App) error {
	if len(app.migrate) == 0 {
		return nil
	}
	workdir, err := s.checkApp(app)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if _, ok := s.readyDatabase(); !ok {
		return fmt.Errorf("migrate: no database: %w", ErrSpec)
	}
	if err := s.clearNetwork(ctx); err != nil {
		return err
	}
	if err := s.claimMigrate(); err != nil {
		return err
	}
	env, envFile, err := s.appEnv(workdir)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	res, err := s.start(ctx, Spec{
		Image: app.Image, Cmd: app.migrate, Env: env, Mounts: []Mount{envFile}, Timeout: migrateTimeout,
		networked: true, workdir: workdir,
	})
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("migrate (exit %d): %w", res.ExitCode, ErrMigrate)
	}
	return nil
}

func (s *Sandbox) claimMigrate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.migrated {
		return fmt.Errorf("the run already ran its migrate step: %w", ErrSpec)
	}
	s.migrated = true
	return nil
}
