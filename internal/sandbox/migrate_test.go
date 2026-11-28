package sandbox

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

// migrateRepo is a repository whose compose file names a migrate step.
func migrateRepo() Repo {
	return (&memRepo{files: map[string]string{
		"compose.yaml": "services:\n  web:\n    build: .\n  migrate:\n    build: .\n    command: [\"--privileged\", \"-v\", \"/:/host\"]\n",
		"Dockerfile":   plainDockerfile, "app.py": "print(1)\n", ".env": "DATABASE_URL=postgres://real:" + hostMarker + "@prod\n",
	}}).repo()
}

// migrateRun is the one run of the built image that is not detached: the
// migrate step.
func migrateRun(t *testing.T, rec *recorder) []string {
	t.Helper()
	var runs [][]string
	for _, argv := range rec.to("run") {
		if slices.Contains(argv, builtImage) && !slices.Contains(argv, "--detach") {
			runs = append(runs, argv)
		}
	}
	if len(runs) != 1 {
		t.Fatalf("%d migrate runs: %q", len(runs), runs)
	}
	return runs[0]
}

// TestMigrateRunsInSandbox is the protection test for the app's migrate
// step (#364): it runs once, after the canary, in the image Build made,
// hardened, on the run network, with only the synthetic env, and its
// arguments follow the image, so even flags the repository wrote are the
// container's command, never the runtime's options. The repository's
// .env and the host's environment never reach it.
func TestMigrateRunsInSandbox(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://real:"+hostMarker+"@prod.example/app")
	rec := withBuilds(networkRecorder(goodCanary, 0), 0)
	s := testSandbox(t, rec)
	app, err := s.Build(context.Background(), migrateRepo())
	if err != nil || !app.Built() {
		t.Fatalf("Build = %+v, %v", app, err)
	}
	if err := s.Migrate(context.Background(), app); !errors.Is(err, ErrSpec) {
		t.Fatalf("Migrate before the database: %v", err)
	}
	db, err := s.StartDatabase(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	canaries := len(canaryRuns(rec))
	if err := s.Migrate(context.Background(), app); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if len(canaryRuns(rec)) != canaries+1 {
		t.Error("the migrate step ran without a canary before it")
	}
	argv := migrateRun(t, rec)
	if p := hardeningProblems(argv); len(p) > 0 {
		t.Errorf("migrate run %q: %v", argv, p)
	}
	at := slices.Index(argv, builtImage)
	if !slices.Equal(argv[at+1:], []string{"--privileged", "-v", "/:/host"}) || slices.Contains(argv[:at], "--privileged") {
		t.Errorf("migrate run %q: the step must follow the image", argv)
	}
	for _, want := range []string{"--network=creep-" + testRunID, "--workdir=/"} {
		if !slices.Contains(argv, want) {
			t.Errorf("migrate run lacks %s: %q", want, argv)
		}
	}
	for _, want := range []string{"DATABASE_URL=" + db.URL(), "PGPASSWORD=" + db.Password} {
		if !slices.Contains(rec.envOf(argv), want) {
			t.Errorf("migrate env file lacks %s: %q", want, rec.envOf(argv))
		}
	}
	checkNoHostData(t, rec)
	if err := s.Migrate(context.Background(), app); !errors.Is(err, ErrSpec) {
		t.Errorf("second Migrate: %v", err)
	}
}

// TestMigrateOutcomes: no step runs nothing; a step that exits non-zero
// is ErrMigrate; an image this sandbox did not build is refused; an
// aborted run starts nothing.
func TestMigrateOutcomes(t *testing.T) {
	plain := withBuilds(networkRecorder(goodCanary, 0), 0)
	s := testSandbox(t, plain)
	app, err := s.Build(context.Background(), dockerfileRepo(plainDockerfile))
	if err != nil || len(app.MigrateCommand()) != 0 {
		t.Fatalf("Build = %+v, %v", app, err)
	}
	runs := len(plain.to("run"))
	if err := s.Migrate(context.Background(), app); err != nil || len(plain.to("run")) != runs {
		t.Errorf("Migrate without a step: %v, %d runs", err, len(plain.to("run"))-runs)
	}

	failing := withBuilds(networkRecorder(goodCanary, 0), 0)
	inner := failing.reply
	failing.reply = func(ctx context.Context, args []string) (cliResult, error) {
		if subcommand(args) == "run" && slices.Contains(args, builtImage) {
			return cliResult{exit: 3}, nil
		}
		return inner(ctx, args)
	}
	s = testSandbox(t, failing)
	if app, err = s.Build(context.Background(), migrateRepo()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartDatabase(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background(), app); !errors.Is(err, ErrMigrate) {
		t.Errorf("failing step: %v, want ErrMigrate", err)
	}
	other := testSandbox(t, withBuilds(networkRecorder(goodCanary, 0), 0))
	if err := other.Migrate(context.Background(), app); !errors.Is(err, ErrSpec) {
		t.Errorf("an image another sandbox built: %v", err)
	}

	leak := withBuilds(networkRecorder(goodCanary, 0), 0)
	s = testSandbox(t, leak)
	if app, err = s.Build(context.Background(), migrateRepo()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartDatabase(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.abort(ErrNetworkLeak)
	if err := s.Migrate(context.Background(), app); !errors.Is(err, ErrNetworkLeak) {
		t.Errorf("Migrate after an abort: %v", err)
	}
}

// TestAppGetsSyntheticEnv: the app gets the run database's settings, all
// creep's own, in its environment and as a .env file mounted read-only in
// its working directory; without a database both are empty. Nothing of
// the host's environment or the repository's .env is in either.
func TestAppGetsSyntheticEnv(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://real:"+hostMarker+"@prod.example/app")
	t.Setenv("PGPASSWORD", hostMarker)
	for _, withDB := range []bool{true, false} {
		rec := withBuilds(networkRecorder(goodCanary, 0), 0)
		s := testSandbox(t, rec)
		var db Database
		if withDB {
			var err error
			if db, err = s.StartDatabase(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		app, err := s.Build(context.Background(), dockerfileRepo(plainDockerfile))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.StartApp(context.Background(), app); err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(rec.to("run"), func(a []string) bool { return slices.Contains(a, "--detach") && slices.Contains(a, builtImage) })
		if i < 0 {
			t.Fatalf("no app run in %q", rec.calls)
		}
		argv := rec.to("run")[i]
		file := envFileOf(t, argv)
		want := ""
		if withDB {
			want = "DATABASE_URL=" + db.URL() + "\nPGDATABASE=app\nPGHOST=db\nPGPASSWORD=" + db.Password + "\nPGPORT=5432\nPGUSER=creep\n"
		}
		if file != want {
			t.Errorf("database %t: .env %q, want %q", withDB, file, want)
		}
		for _, line := range strings.Split(strings.TrimSpace(want), "\n") {
			if line != "" && !slices.Contains(rec.envOf(argv), line) {
				t.Errorf("database %t: app env lacks %s", withDB, line)
			}
		}
		checkNoHostData(t, rec)
	}
}

// envFileOf reads the .env file mounted in the app's working directory.
func envFileOf(t *testing.T, argv []string) string {
	t.Helper()
	i := slices.IndexFunc(argv, func(a string) bool { return strings.HasSuffix(a, ",target=/"+envFileName+",readonly") })
	if i < 0 {
		t.Fatalf("no .env mount in %q", argv)
	}
	src, _, _ := strings.Cut(strings.TrimPrefix(argv[i], "--mount=type=bind,source="), ",target=")
	data, err := os.ReadFile(src) //nolint:gosec // G304: the env file this test's sandbox wrote
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func checkNoHostData(t *testing.T, rec *recorder) {
	t.Helper()
	for _, c := range rec.calls {
		if strings.Contains(strings.Join(c, " "), hostMarker) {
			t.Errorf("host data in %q", c)
		}
		if env := rec.envOf(c); strings.Contains(strings.Join(env, "\n"), hostMarker) {
			t.Errorf("host data in the env file of %q: %q", c, env)
		}
	}
}

// canaryRuns are the canary's runs so far.
func canaryRuns(rec *recorder) [][]string {
	return slices.DeleteFunc(rec.to("run"), func(argv []string) bool {
		return !slices.Contains(argv, CanaryImage) || isRunnerRun(argv)
	})
}

// TestWriteEnvFileRefuses: a name or value that could split a line, a
// proxy variable or too many names writes nothing.
func TestWriteEnvFileRefuses(t *testing.T) {
	s := testSandbox(t, &recorder{})
	many := map[string]string{}
	for i := range maxEnv + 1 {
		many["V"+strings.Repeat("A", i+1)] = "x"
	}
	for name, env := range map[string]map[string]string{
		"name with =": {"A=B": "x"}, "flag name": {"-e": "x"}, "line break": {"A": "x\nB=y"},
		"proxy": {"HTTPS_PROXY": "http://evil"}, "too many": many,
	} {
		if _, err := s.writeEnvFile(env); !errors.Is(err, ErrSpec) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
