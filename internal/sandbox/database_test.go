package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// hostMarker stands for data on the host: an operator variable and a file
// next to the migrations. Neither may reach the database.
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

// databaseProblems checks the database's command line: the seed is the
// only bind mount and lies in the work directory, the data directories
// are tmpfs, nothing names a volume, and every variable is the fixed set
// with synthetic values.
func databaseProblems(argv []string, work string) []string {
	var problems []string
	mounts := 0
	for _, a := range argv[:slices.Index(argv, DatabaseImage)] {
		switch {
		case strings.HasPrefix(a, "--mount="):
			mounts++
			src, _, _ := strings.Cut(strings.TrimPrefix(a, "--mount=type=bind,source="), ",")
			if !strings.HasPrefix(a, "--mount=type=bind,source=") || !strings.HasPrefix(src, work+string(filepath.Separator)) ||
				!strings.HasSuffix(a, ",target="+seedTarget+",readonly") {
				problems = append(problems, "mount "+a)
			}
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
	if mounts != 1 {
		problems = append(problems, "want exactly the seed mounted")
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
// database: its container mounts only the seed creep wrote in its work
// directory, keeps its data on tmpfs, gets only synthetic credentials, and
// the seed holds the migrations and nothing else; host data in the
// environment or beside the migrations never reaches it. Each weakened
// command line is caught.
func TestDatabaseMountsNoHostPath(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://real:"+hostMarker+"@prod.example/app")
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("DB_PASSWORD="+hostMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := networkRecorder(goodCanary, 0)
	s := testSandbox(t, rec)
	migrations := []Migration{
		{Path: "migrations/1_init.sql", SQL: []byte("CREATE TABLE items (id int);")},
		{Path: "migrations/2_seed.sql", SQL: []byte("INSERT INTO items VALUES (1)")},
	}
	db, err := s.StartDatabase(context.Background(), migrations)
	if err != nil {
		t.Fatal(err)
	}
	argv := databaseRun(t, rec)
	if p := append(hardeningProblems(argv), databaseProblems(argv, s.workReal)...); len(p) > 0 {
		t.Errorf("database run %q: %v", argv, p)
	}
	checkSeed(t, argv, migrations)
	for _, c := range rec.calls {
		if strings.Contains(strings.Join(c, " "), hostMarker) {
			t.Errorf("host data in %q", c)
		}
	}
	if !strings.HasPrefix(db.Password, "creep-synthetic-") || db.URL() != "postgres://creep:"+db.Password+"@db:5432/app?sslmode=disable" {
		t.Errorf("database %+v, URL %s", db, db.URL())
	}
	for name, weak := range databaseWeakened(argv, repo) {
		if len(databaseProblems(weak, s.workReal))+len(hardeningProblems(weak)) == 0 {
			t.Errorf("%s: weakened database run %q passed", name, weak)
		}
	}
}

// checkSeed reads the mounted seed: exactly the migrations, in order.
func checkSeed(t *testing.T, argv []string, migrations []Migration) {
	t.Helper()
	i := slices.IndexFunc(argv, func(a string) bool { return strings.HasPrefix(a, "--mount=") })
	src, _, _ := strings.Cut(strings.TrimPrefix(argv[i], "--mount=type=bind,source="), ",")
	got, err := os.ReadFile(src) //nolint:gosec // G304: the seed this test's sandbox wrote
	if err != nil {
		t.Fatal(err)
	}
	want, _ := seedSQL(migrations)
	if string(got) != string(want) || !strings.Contains(string(got), "CREATE TABLE items") ||
		strings.Index(string(got), "CREATE TABLE") > strings.Index(string(got), "INSERT INTO") {
		t.Errorf("seed:\n%s", got)
	}
}

func databaseWeakened(good []string, repo string) map[string][]string {
	insert := func(extra ...string) []string {
		i := slices.Index(good, "run") + 1
		return slices.Insert(slices.Clone(good), i, extra...)
	}
	return map[string][]string{
		"host data dir":     insert("--mount=type=bind,source=" + repo + ",target=" + pgData + ",readonly"),
		"host .env":         insert("--mount=type=bind,source=" + filepath.Join(repo, ".env") + ",target=/app/.env,readonly"),
		"named volume":      insert("--mount=type=volume,source=pgdata,target=" + pgData),
		"volume flag":       insert("--volume=pgdata:" + pgData),
		"short volume flag": insert("-v", repo+":/seed"),
		"volumes from":      insert("--volumes-from=prod-db"),
		"host variable":     insert("--env=DATABASE_URL=postgres://real:" + hostMarker + "@prod.example/app"),
		"real password":     insert("--env=POSTGRES_PASSWORD=" + hostMarker),
		"other tmpfs":       insert("--tmpfs=/srv:" + serviceTmpfs),
	}
}

// TestStartDatabaseFails: a seed that is too big, binary or too long
// starts nothing; a database that never gets ready (a failed migration)
// is ErrDatabase; a second database is refused; an image VOLUME that no
// tmpfs covers is refused.
func TestStartDatabaseFails(t *testing.T) {
	big := make([]Migration, maxMigrations+1)
	tests := map[string]struct {
		migrations []Migration
		ready      int
		volumes    string
		want       error
		started    bool // the database container started
	}{
		"too many migrations": {migrations: big, want: ErrSpec},
		"migration too large": {migrations: []Migration{{Path: "m.sql", SQL: bytes.Repeat([]byte("-"), maxMigrationSize+1)}}, want: ErrSpec},
		"binary migration":    {migrations: []Migration{{Path: "m.sql", SQL: []byte("SELECT 1;\x00")}}, want: ErrSpec},
		"seed too large":      {migrations: slices.Repeat([]Migration{{SQL: bytes.Repeat([]byte("-"), maxMigrationSize)}}, 9), want: ErrSpec},
		"never ready":         {ready: 1, want: ErrDatabase, started: true},
		"uncovered volume":    {volumes: `{"/var/lib/postgresql/data":{},"/backup":{}}`, want: ErrImageVolumes},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rec := networkRecorder(goodCanary, tt.ready)
			if tt.volumes != "" {
				rec.images[DatabaseImage] = cliResult{stdout: []byte(tt.volumes)}
			}
			s := testSandbox(t, rec)
			if _, err := s.StartDatabase(context.Background(), tt.migrations); !errors.Is(err, tt.want) {
				t.Fatalf("StartDatabase: %v, want %v", err, tt.want)
			}
			started := slices.ContainsFunc(rec.to("run"), func(a []string) bool { return slices.Contains(a, "--detach") })
			if started != tt.started {
				t.Errorf("database started %v, want %v", started, tt.started)
			}
		})
	}
	s := testSandbox(t, networkRecorder(goodCanary, 0))
	if _, err := s.StartDatabase(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartDatabase(context.Background(), nil); !errors.Is(err, ErrSpec) {
		t.Errorf("second database: %v", err)
	}
}
