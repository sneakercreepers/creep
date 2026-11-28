package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// hostMarker stands for data on the host: an operator variable and a file
// in the repository. Neither may reach the database.
const hostMarker = "host-data-marker-7f3a91"

// databaseRun is the detached run of the database service.
func databaseRun(t *testing.T, rec *recorder) []string {
	t.Helper()
	for _, argv := range rec.to("run") {
		if slices.Contains(argv, "--detach") && slices.Contains(argv, DatabaseImage) {
			return argv
		}
	}
	t.Fatalf("no database run in %q", rec.calls)
	return nil
}

// databaseProblems checks the database's command line: nothing is
// mounted (the app's migrate step sets up the schema, #364), the data
// directories are tmpfs, nothing names a volume, and every variable, on
// the command line or in its env file, is the fixed set with synthetic
// values.
func databaseProblems(argv, env []string) []string {
	var problems []string
	for _, kv := range env {
		problems = append(problems, envProblem(kv)...)
	}
	for _, a := range argv[:slices.Index(argv, DatabaseImage)] {
		switch {
		case strings.HasPrefix(a, "--mount="):
			problems = append(problems, "mount "+a)
		case a == "-v", strings.HasPrefix(a, "--volume"), strings.HasPrefix(a, "-v="), strings.HasPrefix(a, "--volumes-from"):
			problems = append(problems, "volume "+a)
		case strings.HasPrefix(a, "--tmpfs=") && !strings.HasPrefix(a, "--tmpfs=/tmp:"):
			if t := strings.TrimPrefix(a, "--tmpfs="); t != pgData+":"+serviceTmpfs && t != pgSocket+":"+serviceTmpfs {
				problems = append(problems, "tmpfs "+a)
			}
		case strings.HasPrefix(a, "--env="):
			problems = append(problems, envProblem(strings.TrimPrefix(a, "--env="))...)
		}
	}
	return problems
}

func envProblem(kv string) []string {
	name, value, _ := strings.Cut(kv, "=")
	fixed := map[string]string{"POSTGRES_USER": databaseUser, "POSTGRES_DB": databaseName, "PGDATA": pgData + "/pgdata"}
	switch {
	case isProxyVar(name) && value == "":
		return nil
	case name == "POSTGRES_PASSWORD" && strings.HasPrefix(value, "creep-synthetic-"):
		return nil
	case fixed[name] != "" && fixed[name] == value:
		return nil
	}
	return []string{"env " + kv}
}

// TestDatabaseMountsNoHostPath is the protection test for the synthetic
// database: its container mounts nothing, keeps its data on tmpfs and
// gets only synthetic credentials; host data in the environment or in the
// repository never reaches it. Each weakened command line is caught.
func TestDatabaseMountsNoHostPath(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://real:"+hostMarker+"@prod.example/app")
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("DB_PASSWORD="+hostMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := networkRecorder(goodCanary, 0)
	s := testSandbox(t, rec)
	db, err := s.StartDatabase(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	argv := databaseRun(t, rec)
	env := rec.envOf(argv)
	if !slices.Contains(env, "POSTGRES_PASSWORD="+db.Password) {
		t.Errorf("database env file %q lacks the synthetic password", env)
	}
	if p := append(hardeningProblems(argv), databaseProblems(argv, env)...); len(p) > 0 {
		t.Errorf("database run %q: %v", argv, p)
	}
	checkNoHostData(t, rec)
	if !strings.HasPrefix(db.Password, "creep-synthetic-") || db.URL() != "postgres://creep:"+db.Password+"@db:5432/app?sslmode=disable" {
		t.Errorf("database %+v, URL %s", db, db.URL())
	}
	for name, weak := range databaseWeakened(argv, repo, s.workReal) {
		if len(databaseProblems(weak, env))+len(hardeningProblems(weak)) == 0 {
			t.Errorf("%s: weakened database run %q passed", name, weak)
		}
	}
	for name, weak := range map[string][]string{
		"host variable in env file": append(slices.Clone(env), "DATABASE_URL=postgres://real:"+hostMarker+"@prod.example/app"),
		"real password in env file": {"POSTGRES_PASSWORD=" + hostMarker},
	} {
		if len(databaseProblems(argv, weak)) == 0 {
			t.Errorf("%s: weakened database env %q passed", name, weak)
		}
	}
}

func databaseWeakened(good []string, repo, work string) map[string][]string {
	insert := func(extra ...string) []string {
		i := slices.Index(good, "run") + 1
		return slices.Insert(slices.Clone(good), i, extra...)
	}
	return map[string][]string{
		"host data dir":     insert("--mount=type=bind,source=" + repo + ",target=" + pgData + ",readonly"),
		"host .env":         insert("--mount=type=bind,source=" + filepath.Join(repo, ".env") + ",target=/app/.env,readonly"),
		"seed from work":    insert("--mount=type=bind,source=" + filepath.Join(work, "seed.sql") + ",target=/docker-entrypoint-initdb.d/seed.sql,readonly"),
		"named volume":      insert("--mount=type=volume,source=pgdata,target=" + pgData),
		"volume flag":       insert("--volume=pgdata:" + pgData),
		"short volume flag": insert("-v", repo+":/seed"),
		"volumes from":      insert("--volumes-from=prod-db"),
		"host variable":     insert("--env=DATABASE_URL=postgres://real:" + hostMarker + "@prod.example/app"),
		"real password":     insert("--env=POSTGRES_PASSWORD=" + hostMarker),
		"other tmpfs":       insert("--tmpfs=/srv:" + serviceTmpfs),
	}
}

// TestStartDatabaseFails: a database that never gets ready is
// ErrDatabase; a second database is refused; an image VOLUME that no
// tmpfs covers is refused.
func TestStartDatabaseFails(t *testing.T) {
	tests := map[string]struct {
		ready   int
		volumes string
		want    error
		started bool // the database container started
	}{
		"never ready":      {ready: 1, want: ErrDatabase, started: true},
		"uncovered volume": {volumes: `{"/var/lib/postgresql/data":{},"/backup":{}}`, want: ErrImageVolumes},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rec := networkRecorder(goodCanary, tt.ready)
			if tt.volumes != "" {
				rec.images[DatabaseImage] = cliResult{stdout: []byte(tt.volumes)}
			}
			s := testSandbox(t, rec)
			if _, err := s.StartDatabase(context.Background()); !errors.Is(err, tt.want) {
				t.Fatalf("StartDatabase: %v, want %v", err, tt.want)
			}
			started := slices.ContainsFunc(rec.to("run"), func(a []string) bool { return slices.Contains(a, "--detach") })
			if started != tt.started {
				t.Errorf("database started %v, want %v", started, tt.started)
			}
		})
	}
	s := testSandbox(t, networkRecorder(goodCanary, 0))
	if _, err := s.StartDatabase(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartDatabase(context.Background()); !errors.Is(err, ErrSpec) {
		t.Errorf("second database: %v", err)
	}
}
