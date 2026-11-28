package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/bench"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway/gatewaytest"
)

// liveBenchFixtureEnv names a fixture `creep bench --record` wrote in the
// live-record workflow, for -update to import (#356).
const liveBenchFixtureEnv = "CREEP_LIVE_BENCH_FIXTURE"

// placeholderEndpoint replaces the recorded endpoint: the request bodies
// do not depend on it and replay never sends there.
const placeholderEndpoint = "https://models.replay.invalid/v1"

// updatePublishedBench imports a live fixture when one is named and
// rewrites docs/bench from the committed fixture otherwise. Only a
// synthesized fixture is regenerated from the oracle; a live one is never
// overwritten without a new live recording.
func updatePublishedBench(t *testing.T) {
	t.Helper()
	if path := os.Getenv(liveBenchFixtureEnv); path != "" {
		importLiveBench(t, path)
		return
	}
	fix, err := bench.Published()
	if err != nil {
		t.Fatal(err)
	}
	if fix.Synthesized {
		writePublishedBench(t)
		return
	}
	writeReplayedResults(t)
}

// importLiveBench writes the recording at path as the published fixture:
// the endpoint replaced by a placeholder and each reply body normalized
// (gatewaytest.Normalize), so it keeps the model's message content and
// drops the provider's response ID and metadata. docs/bench is written
// from a replay of the result in a separate run, since the fixture is
// embedded: rerun -update without the variable.
func importLiveBench(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: the workflow's own recording
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fix, err := bench.ParseFixture(f)
	if err != nil {
		t.Fatal(err)
	}
	if fix.Synthesized {
		t.Fatal("the recording to import says it is synthesized")
	}
	fix.Model.Endpoint = placeholderEndpoint
	for i, r := range fix.Replies {
		body, err := gatewaytest.Normalize([]byte(r.Body))
		if err != nil {
			t.Fatalf("reply %s: %v", r.Request, err)
		}
		fix.Replies[i].Body = string(body)
	}
	out, err := fix.JSON()
	if err != nil {
		t.Fatal(err)
	}
	writeBenchFile(t, publishedFixturePath, string(out))
}

// writeReplayedResults rewrites docs/bench from creep bench --replay of
// the committed fixture.
func writeReplayedResults(t *testing.T) {
	t.Helper()
	dir, _ := os.Getwd()
	isolateUserConfig(t)
	t.Chdir(t.TempDir())
	for _, tc := range []struct{ format, file string }{{"json", "results.json"}, {"markdown", "results.md"}} {
		code, stdout, stderr := runScanWith(noModelDeps, "bench", "--replay", "--format", tc.format)
		if !benchFinished(code) {
			t.Fatalf("%s: exit %d, stderr %q", tc.format, code, stderr)
		}
		writeBenchFile(t, filepath.Join(dir, publishedResultsDir, tc.file), stdout)
	}
}

// benchFinished is a bench that printed its results: exit 4 means some
// case runs were incomplete, as a small live model's are, and the results
// count them (incomplete_runs), so the published numbers pin them.
func benchFinished(code int) bool {
	return code == exitcode.OK || code == exitcode.Incomplete
}

// Acceptance (#356): the published fixture is live, names no endpoint
// and holds no provider response ID, key or routing field.
func TestPublishedBenchIsLiveAndClean(t *testing.T) {
	fix, err := bench.Published()
	if err != nil {
		t.Fatal(err)
	}
	if fix.Synthesized || fix.Model.Endpoint != placeholderEndpoint {
		t.Fatalf("published fixture: synthesized %v, endpoint %q", fix.Synthesized, fix.Model.Endpoint)
	}
	for _, r := range fix.Replies {
		if err := gatewaytest.CheckReplyHygiene([]byte(r.Body)); err != nil {
			t.Errorf("reply %s: %v", r.Request, err)
		}
	}
}
