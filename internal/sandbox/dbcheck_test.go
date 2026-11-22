package sandbox

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

const markerName = "creep_0123456789abcdef"

// TestDatabaseHasTable: only creep's marker names are looked up, only in
// the database the run seeded, by a hardened psql on the run network that
// gets the password in its environment; its answer is read strictly.
func TestDatabaseHasTable(t *testing.T) {
	for _, name := range []string{"users", "creep_", "creep_0123", "CREEP_0123456789ABCDEF", "creep_0123456789abcdef'; DROP TABLE x; --", "creep_0123456789abcdef x"} {
		rec := networkRecorder(goodCanary, 0)
		s := testSandbox(t, rec)
		if _, err := s.StartDatabase(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		before := len(rec.to("run"))
		if _, err := s.DatabaseHasTable(context.Background(), name); !errors.Is(err, ErrSpec) || len(rec.to("run")) != before {
			t.Errorf("name %q: %v", name, err)
		}
	}
	rec := networkRecorder(goodCanary, 0)
	if _, err := testSandbox(t, rec).DatabaseHasTable(context.Background(), markerName); !errors.Is(err, ErrSpec) || len(rec.calls) != 0 {
		t.Errorf("no database: %v, %q", err, rec.calls)
	}
	tests := map[string]struct {
		answer cliResult
		want   bool
		err    error
	}{
		"present":   {cliResult{stdout: []byte("t\n")}, true, nil},
		"absent":    {cliResult{stdout: []byte("f\n")}, false, nil},
		"odd":       {cliResult{stdout: []byte("t\nf\n")}, false, ErrRunnerAnswer},
		"psql fail": {cliResult{exit: 2}, false, ErrDatabase},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, argv, err := lookupWith(t, tt.answer)
			if got != tt.want || !errors.Is(err, tt.err) || (tt.err == nil) != (err == nil) {
				t.Fatalf("DatabaseHasTable = %t, %v", got, err)
			}
			checkLookupArgv(t, argv)
		})
	}
}

// lookupWith starts the database, answers the lookup with answer and
// returns its result and argv.
func lookupWith(t *testing.T, answer cliResult) (bool, []string, error) {
	t.Helper()
	rec := networkRecorder(goodCanary, 0)
	plain := rec.reply
	rec.reply = func(ctx context.Context, args []string) (cliResult, error) {
		if slices.Contains(args, "psql") {
			return answer, nil
		}
		return plain(ctx, args)
	}
	s := testSandbox(t, rec)
	db, err := s.StartDatabase(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.DatabaseHasTable(context.Background(), markerName)
	runs := rec.to("run")
	argv := runs[len(runs)-1]
	for _, a := range argv {
		if strings.Contains(a, db.Password) && a != "--env=PGPASSWORD="+db.Password {
			t.Errorf("the password is on the command line: %q", a)
		}
	}
	return got, argv, err
}

func checkLookupArgv(t *testing.T, argv []string) {
	t.Helper()
	if p := hardeningProblems(argv); len(p) > 0 {
		t.Errorf("lookup %q: %v", argv, p)
	}
	img := slices.Index(argv, DatabaseImage)
	want := []string{"psql", "-X", "-q", "-t", "-A", "-h", "db", "-p", "5432", "-U", "creep", "-d", "app", "-c",
		"SELECT to_regclass('public." + markerName + "') IS NOT NULL"}
	if img < 0 || !slices.Equal(argv[img+1:], want) || !slices.Contains(argv, "--network=creep-"+testRunID) {
		t.Errorf("lookup %q", argv)
	}
}
