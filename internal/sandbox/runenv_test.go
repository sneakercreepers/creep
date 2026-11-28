package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// keepEnv records the lines of the env file a run reads; the caller holds
// r.mu. The file exists only while the run is in flight.
func (r *recorder) keepEnv(args []string) {
	i := slices.IndexFunc(args, func(a string) bool { return strings.HasPrefix(a, "--env-file=") })
	if i < 0 {
		return
	}
	data, err := os.ReadFile(strings.TrimPrefix(args[i], "--env-file=")) //nolint:gosec // G304: the env file this test's sandbox wrote
	if err != nil {
		return
	}
	if r.envs == nil {
		r.envs = map[string][]string{}
	}
	r.envs[containerName(args)] = strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// envOf is the env a recorded run got from its env file.
func (r *recorder) envOf(argv []string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.envs[containerName(argv)]
}

func containerName(args []string) string {
	for _, a := range args {
		if name, ok := strings.CutPrefix(a, "--name="); ok {
			return name
		}
	}
	return ""
}

// argvLeaks lists every recorded command line that holds one of values.
func argvLeaks(calls [][]string, values []string) []string {
	var leaks []string
	for _, c := range calls {
		line := strings.Join(c, " ")
		for _, v := range values {
			if strings.Contains(line, v) {
				leaks = append(leaks, line)
			}
		}
	}
	return leaks
}

// TestSyntheticEnvNeverOnArgv is the protection test for #374: no
// synthetic value (the database password, its URL, a spec's own value)
// is on any command line the sandbox runs, where every host user could
// read it in the process list. Each container that needs them (the
// database, the migrate step, the app, the marker lookup, a PoC) reads
// them from a creep-owned env file, which is gone once the run returned.
// A command line carrying a value is caught.
func TestSyntheticEnvNeverOnArgv(t *testing.T) {
	rec := withBuilds(networkRecorder(goodCanary, 0), 0)
	s := testSandbox(t, rec)
	ctx := context.Background()
	const marker = "creep-synthetic-argv-marker"
	poc := Spec{Image: testImage, Env: map[string]string{"SECRET_KEY": marker}}
	if _, err := s.Run(ctx, poc); err != nil {
		t.Fatal(err)
	}
	app, err := s.Build(ctx, migrateRepo())
	if err != nil || !app.Built() {
		t.Fatalf("Build = %+v, %v", app, err)
	}
	db, err := s.StartDatabase(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx, app); err != nil {
		t.Fatal(err)
	}
	if err := s.StartApp(ctx, app); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DatabaseHasTable(ctx, markerName); err != nil {
		t.Fatal(err)
	}
	secrets := []string{marker, db.Password, db.URL()}
	for _, leak := range argvLeaks(rec.calls, secrets) {
		t.Errorf("synthetic value on the command line: %s", leak)
	}
	checkEnvReachedEach(t, rec, db, marker)
	if left, _ := filepath.Glob(filepath.Join(s.workReal, runEnvPrefix+"*")); len(left) > 0 {
		t.Errorf("env files left after their runs: %q", left)
	}
	good := rec.to("run")[0]
	weak := slices.Insert(slices.Clone(good), slices.Index(good, "run")+1, "--env=PGPASSWORD="+db.Password)
	if len(argvLeaks([][]string{weak}, secrets)) == 0 || len(hardeningProblems(weak)) == 0 {
		t.Errorf("a password on the command line passed: %q", weak)
	}
}

// checkEnvReachedEach proves the test is not vacuous: every container
// that needs a synthetic value got it from its env file.
func checkEnvReachedEach(t *testing.T, rec *recorder, db Database, marker string) {
	t.Helper()
	runs := rec.to("run")
	built := func(detached bool) func([]string) bool {
		return func(a []string) bool {
			return slices.Contains(a, builtImage) && slices.Contains(a, "--detach") == detached
		}
	}
	password := "PGPASSWORD=" + db.Password
	want := []struct {
		run   string
		line  string
		isRun func([]string) bool
	}{
		{"poc", "SECRET_KEY=" + marker, func(a []string) bool { return slices.Contains(a, testImage) }},
		{"database", "POSTGRES_PASSWORD=" + db.Password, func(a []string) bool { return slices.Contains(a, "--network-alias="+databaseAlias) }},
		{"migrate", password, built(false)},
		{"app", password, built(true)},
		{"lookup", password, func(a []string) bool { return slices.Contains(a, "psql") }},
	}
	for _, w := range want {
		i := slices.IndexFunc(runs, w.isRun)
		if i < 0 || !slices.Contains(rec.envOf(runs[i]), w.line) {
			t.Errorf("%s run did not get %s from its env file", w.run, w.line)
		}
	}
}

// TestRunEnvFile: the env file is creep's own, created new and readable
// only by this user, and a value two runtimes could read differently, or
// one that could split a line, writes nothing.
func TestRunEnvFile(t *testing.T) {
	s := testSandbox(t, &recorder{})
	file, err := s.writeRunEnv("creep-x-1", map[string]string{"B": "2", "A": "x=y"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file) //nolint:gosec // G304: the file this test's sandbox wrote
	if err != nil || string(data) != "A=x=y\nB=2\n" {
		t.Errorf("env file %q, %v", data, err)
	}
	if info, err := os.Stat(file); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Errorf("env file mode: %v, %v", info, err)
	}
	if _, err := s.writeRunEnv("creep-x-1", map[string]string{"A": "y"}); err == nil {
		t.Error("an existing env file was overwritten")
	}
	s.removeRunEnv("creep-x-1")
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("env file not removed: %v", err)
	}
	for name, env := range map[string]map[string]string{
		"double quote": {"A": `"x"`}, "single quote": {"A": "'x'"}, "invalid utf-8": {"A": "\xff"},
		"line break": {"A": "x\nB=y"}, "carriage return": {"A": "x\rB=y"}, "nul": {"A": "x\x00"},
		"bare name": {"A=B": "x"}, "proxy": {"no_proxy": "*"},
	} {
		if _, err := s.writeRunEnv("creep-x-2", env); !errors.Is(err, ErrSpec) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(s.workReal, runEnvPrefix+"creep-x-2")); len(left) > 0 {
		t.Error("a refused env wrote a file")
	}
}
