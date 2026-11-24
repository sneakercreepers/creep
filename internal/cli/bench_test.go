package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/bench"
	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/state"
)

// publishedModel is the client the published fixture was made with.
var publishedModel = bench.FixtureModel{
	Contract: "openai", Endpoint: "https://models.replay.invalid/v1", Name: "replay-model",
	Structured: string(models.StructuredSchema), MaxOutputTokens: replyTokens, Retries: 1,
}

var (
	publishedFixturePath = filepath.Join("..", "bench", "fixtures", "published.json")
	publishedResultsDir  = filepath.Join("..", "..", "docs", "bench")
)

// Acceptance (#35): creep bench --replay reproduces the published numbers,
// in JSON and Markdown, with no network, no key, no config and no state.
// Regenerate the fixture and the numbers from the oracle after changing
// the corpus, a prompt, the pipeline or the scoring:
//
//	go test ./internal/cli -run TestBenchPublished -update
func TestBenchPublished(t *testing.T) {
	if *updateGolden {
		writePublishedBench(t)
		t.Skip("rewrote the published fixture and results; rerun without -update to check them")
	}
	dir, _ := os.Getwd()
	isolateUserConfig(t)
	t.Chdir(t.TempDir())
	for _, tc := range []struct{ format, file string }{{"json", "results.json"}, {"text", "results.md"}, {"markdown", "results.md"}} {
		code, stdout, stderr := runScanWith(noModelDeps, "bench", "--replay", "--format", tc.format)
		if code != exitcode.OK {
			t.Fatalf("%s: exit %d, stderr %q", tc.format, code, stderr)
		}
		want, err := os.ReadFile(filepath.Join(dir, publishedResultsDir, tc.file))
		if err != nil {
			t.Fatal(err)
		}
		if stdout != string(want) {
			t.Errorf("%s: creep bench --replay differs from docs/bench/%s (rerun with -update):\n%s", tc.format, tc.file, stdout)
		}
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Errorf("a replayed bench wrote %s: %v", stateDir, err)
	}
}

// writePublishedBench runs the bench against the oracle, recording every
// reply, and writes the fixture and the results it gives.
func writePublishedBench(t *testing.T) {
	t.Helper()
	cases, err := bench.Corpus()
	if err != nil {
		t.Fatal(err)
	}
	rec := bench.NewRecorder()
	oracle := &benchOracle{cases: cases}
	m, err := models.NewHTTP(fixtureOptions(publishedModel, recordingSend(rec, oracle.send)))
	if err != nil {
		t.Fatal(err)
	}
	outcomes, err := benchAll(context.Background(), m, cases)
	if err != nil {
		t.Fatal(err)
	}
	fix, err := rec.Fixture(publishedModel, true).JSON()
	if err != nil {
		t.Fatal(err)
	}
	writeBenchFile(t, publishedFixturePath, string(fix))
	res, err := benchResults(benchClients{fixture: publishedModel, synthesized: true}, cases, outcomes)
	if err != nil {
		t.Fatal(err)
	}
	out, err := res.JSON()
	if err != nil {
		t.Fatal(err)
	}
	writeBenchFile(t, filepath.Join(publishedResultsDir, "results.json"), string(out))
	writeBenchFile(t, filepath.Join(publishedResultsDir, "results.md"), res.Markdown())
}

// The published fixture answers every request the bench makes, exactly:
// replaying it calls nothing else, and a fixture without a reply fails
// the bench with exit 3 instead of scoring the gap.
func TestBenchReplayMissFails(t *testing.T) {
	cases, err := bench.Corpus()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	e := env{stdout: &stdout, stderr: &stderr, opts: defaultOptions(), deps: noModelDeps}
	empty := bench.Fixture{SchemaVersion: 1, Synthesized: true, Model: publishedModel}
	if code := replayFixture(e, cases, empty); code != exitcode.ModelOrSandbox {
		t.Fatalf("exit %d, want %d", code, exitcode.ModelOrSandbox)
	}
	if !strings.Contains(stderr.String(), errNoPublishedReply.Error()) || stdout.Len() != 0 {
		t.Errorf("stderr %q, stdout %q", stderr.String(), stdout.String())
	}
}

func TestBenchUsage(t *testing.T) {
	isolateUserConfig(t)
	t.Chdir(t.TempDir())
	for _, args := range [][]string{
		{"bench", "extra"},
		{"bench", "--replay", "--format", "sarif"},
		{"bench", "--replay", "--record"},
	} {
		code, stdout, stderr := runScanWith(noModelDeps, args...)
		if code != exitcode.ConfigError || stdout != "" || stderr == "" {
			t.Errorf("%q: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}
}

// A live bench goes through the run's model link (the gateway in
// production), and --record writes a fixture that replays to the same
// numbers.
func TestBenchRecordReplaysToSameResults(t *testing.T) {
	cfg := scanRepo(t, nil, "")
	cases, err := bench.Corpus()
	if err != nil {
		t.Fatal(err)
	}
	oracle := &benchOracle{cases: cases}
	connected := 0
	deps := scanDeps{connect: func(*config.Resolved, string, io.Writer) (modelLink, error) {
		connected++
		return modelLink{send: oracle.send, close: func() error { return nil }}, nil
	}}
	code, live, stderr := runScanWith(deps, "bench", "--record", "--config", cfg, "--format", "json")
	if code != exitcode.OK || connected != 1 || oracle.calls == 0 {
		t.Fatalf("exit %d, connected %d, calls %d, stderr %q", code, connected, oracle.calls, stderr)
	}
	fix := recordedBenchFixture(t)
	if fix.Synthesized || fix.Model.Name != "test-model" || len(fix.Replies) != oracle.calls {
		t.Fatalf("fixture: synthesized %v, model %q, %d replies for %d calls", fix.Synthesized, fix.Model.Name, len(fix.Replies), oracle.calls)
	}
	var stdout, errOut bytes.Buffer
	e := env{stdout: &stdout, stderr: &errOut, opts: defaultOptions(), deps: noModelDeps}
	e.opts.format = "json"
	if code := replayFixture(e, cases, fix); code != exitcode.OK {
		t.Fatalf("replay exit %d: %s", code, errOut.String())
	}
	if stdout.String() != live {
		t.Errorf("replay of the recorded fixture differs from the live run:\nlive %s\nreplay %s", live, stdout.String())
	}
}

// budget.max_seconds bounds a live bench: a model that never answers ends
// the bench incomplete (exit 4), and its run state says so.
func TestBenchLiveHonorsDeadline(t *testing.T) {
	cfg := scanRepo(t, nil, "budget:\n  max_seconds: 1\n")
	deps := scanDeps{connect: func(*config.Resolved, string, io.Writer) (modelLink, error) {
		hang := func(ctx context.Context, _ gateway.Call) (*gateway.Reply, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return modelLink{send: hang, close: func() error { return nil }}, nil
	}}
	start := time.Now()
	code, _, stderr := runScanWith(deps, "bench", "--config", cfg)
	if code != exitcode.Incomplete || time.Since(start) > 30*time.Second {
		t.Fatalf("exit %d after %s, stderr %q", code, time.Since(start), stderr)
	}
	if sum := lastBenchRun(t); sum.Outcome != state.OutcomeIncomplete {
		t.Errorf("run state %+v, want incomplete", sum)
	}
}

func lastBenchRun(t *testing.T) state.Summary {
	t.Helper()
	s, err := state.OpenUser(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dirs, err := filepath.Glob(filepath.Join(stateDir, "runs", "*"))
	if err != nil || len(dirs) != 1 {
		t.Fatalf("runs %v, %v", dirs, err)
	}
	sum, err := s.Load(filepath.Base(dirs[0]))
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func recordedBenchFixture(t *testing.T) bench.Fixture {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(stateDir, "runs", "*", benchFixtureFile))
	if err != nil || len(paths) != 1 {
		t.Fatalf("recorded fixtures: %v %v", paths, err)
	}
	f, err := os.Open(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fix, err := bench.ParseFixture(f)
	if err != nil {
		t.Fatal(err)
	}
	return fix
}

// A model CLI cannot be benched yet, and nothing connects before the
// config is checked.
func TestBenchRefusesCommandModel(t *testing.T) {
	cfg := scanRepo(t, nil, "")
	data, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	command := strings.Replace(string(data), "contract: openai", "contract: command\n  run: model-cli", 1)
	writeBenchFile(t, cfg, command)
	code, _, stderr := runScanWith(noModelDeps, "bench", "--config", cfg)
	if code != exitcode.ConfigError || !strings.Contains(stderr, "contract command is not supported") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

// Every bench class is a class creep's coverage lists, so a case can be
// scored against what the run claimed.
func TestBenchClassesAreCoverageClasses(t *testing.T) {
	cases, err := bench.Corpus()
	if err != nil {
		t.Fatal(err)
	}
	var known []string
	for _, c := range classCoverage(coverageInput{}) {
		known = append(known, c.Class)
	}
	for _, c := range cases {
		if !slices.Contains(known, c.Class) {
			t.Errorf("case %s: class %q is not in %v", c.ID, c.Class, known)
		}
	}
	if len(known) != len(calibrate.Classes())+1 {
		t.Errorf("coverage classes %v: calibration's and template injection", known)
	}
}

// writeBenchFile writes a published file or a test config.
func writeBenchFile(t *testing.T, path, data string) {
	t.Helper()
	// G703: path is one of this file's constants or a t.TempDir() config.
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}
