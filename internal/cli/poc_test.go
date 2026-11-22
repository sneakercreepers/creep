package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/sandbox"
	"github.com/sneakercreepers/creep/internal/verify"
)

// sqlDelayPoC is the model's PoC for the Flask app's SQL injection.
var sqlDelayPoC = map[string]any{
	"template": "sql_payload", "http_request": nil, "http_sequence": nil, "path_payload": nil,
	"sql_payload": map[string]any{
		"request": map[string]any{"method": "GET", "path": "/users?id=__CREEP_PAYLOAD__", "headers": []any{}, "content_type": "", "body": ""},
		"context": "numeric", "technique": "delay",
	},
}

// pathPoC is a PoC of a template that does not prove SQL injection.
var pathPoC = map[string]any{
	"template": "path_payload", "http_request": nil, "http_sequence": nil, "sql_payload": nil,
	"path_payload": map[string]any{
		"request": map[string]any{"method": "GET", "path": "/file?name=__CREEP_PAYLOAD__", "headers": []any{}, "content_type": "", "body": ""},
		"style":   "absolute", "depth": 0,
	},
}

// delayApp is a deterministic fake app behind the runner: the payload
// request of run i takes 3.1 s when slow[i] (pg_sleep ran), every other
// request 0.1 s, and every answer carries body.
func delayApp(slow []bool, body string) func(int, [][]byte) ([]sandbox.Exchange, error) {
	run := 0
	return func(_ int, requests [][]byte) ([]sandbox.Exchange, error) {
		out := make([]sandbox.Exchange, len(requests))
		for i, r := range requests {
			elapsed := 100 * time.Millisecond
			if bytes.Contains(r, []byte("pg_sleep")) && run < len(slow) && slow[run] {
				elapsed = 3100 * time.Millisecond
			}
			out[i] = sandbox.Exchange{Response: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + body), Elapsed: elapsed}
		}
		run++
		return out, nil
	}
}

func repeatBool(b bool, n int) []bool {
	out := make([]bool, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// pocScan scans the vulnerable Flask app with the sandbox on and a fake
// app at port 5000 behind the runner, and returns the run's exit code,
// output, the fake sandbox and model.
func pocScan(t *testing.T, poc any, exchange func(int, [][]byte) ([]sandbox.Exchange, error)) (int, string, *fakeBuilder, *fakeModel) {
	t.Helper()
	fb := &fakeBuilder{app: builtApp, port: 5000, exchange: exchange}
	m := &fakeModel{verdict: sqliVulnerable, poc: poc}
	opened := 0
	deps := withBuilder(fakeDeps(m, calibrate.TierM), fb, nil, &opened)
	files := map[string]string{"app.py": "@flask", "migrations/1_init.sql": "CREATE TABLE users (id int);\n"}
	code, stdout, stderr := runScanWith(deps, "--config", scanRepo(t, files, sandboxOn), "scan", "--mode", "nightly")
	return code, stdout + stderr, fb, m
}

// sqliFinding is the report's SQL injection finding.
func sqliFinding(t *testing.T) report.Finding {
	t.Helper()
	f, err := os.Open(filepath.Join(stateDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := report.ReadJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range rep.Findings {
		if fd.Class == "sqli" {
			return fd
		}
	}
	t.Fatal("no sqli finding")
	return report.Finding{}
}

// TestPoCRateDecidesStatus (#25): a PoC that verified in every run makes
// its finding verified, an intermittent one verified with its rate in the
// text and Markdown reports, and one that never verified, or that the
// model could not give for the class, leaves the finding probable with no
// bundle. The nightly gate (verified:high) reads the result: a verified
// finding trips it, a PoC that ran and never verified does not, and a PoC
// that did not run reads the gate at probable (ADR 0021).
func TestPoCRateDecidesStatus(t *testing.T) {
	tests := []struct {
		name      string
		poc       any
		slow      []bool
		status    report.Status
		want      []string // in the output and report.md
		exchanges int
		code      int
	}{
		{"stable", sqlDelayPoC, repeatBool(true, 10), report.StatusVerified, []string{"verified in 5/5 runs", "PoCs ran for 2 findings: 2 verified in every run"}, 10, exitcode.GateExceeded},
		{"intermittent", sqlDelayPoC, []bool{true, false, true, true, false}, report.StatusVerified,
			[]string{"verified in 3/5 runs, intermittent", "0 verified in every run, 1 intermittent, 1 not reproduced"}, 10, exitcode.GateExceeded},
		{"never", sqlDelayPoC, nil, report.StatusProbable, []string{"2 not reproduced"}, 10, exitcode.OK},
		{"template of another class", pathPoC, nil, report.StatusProbable, []string{"2 got no PoC run"}, 0, exitcode.GateExceeded},
		{"no valid PoC", nil, nil, report.StatusProbable, []string{"2 got no PoC run"}, 0, exitcode.GateExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, fb, _ := pocScan(t, tt.poc, delayApp(tt.slow, "[]"))
			if code != tt.code {
				t.Fatalf("exit %d\n%s", code, out)
			}
			f := sqliFinding(t)
			if f.Status != tt.status || fb.exchanges != tt.exchanges || fb.started != 1 {
				t.Errorf("status %s, %d exchanges, %d starts\n%s", f.Status, fb.exchanges, fb.started, out)
			}
			assertContains(t, "output", out, tt.want)
			assertContains(t, "report.md", readState(t, "report.md"), tt.want)
			if tt.status == report.StatusProbable && tt.exchanges == 0 {
				assertContains(t, "output", out, []string{`gates.nightly "verified:high" (default) read as "probable:high": 2 probable findings got no PoC run`})
			}
			_, err := os.Stat(filepath.Join(stateDir, bundleName(f.ID)))
			if (err == nil) != (tt.status == report.StatusVerified) {
				t.Errorf("bundle for a %s finding: %v", f.Status, err)
			}
			if len(fb.migrations) != 1 || fb.migrations[0].Path != "migrations/1_init.sql" {
				t.Errorf("database seeded with %+v", fb.migrations)
			}
		})
	}
}

// Protection (#25): no finding is verified by a PoC that verified in no
// run. Every run answers, slowly on baselines and payload alike (a
// tarpit), so nothing but the oracle can decide; the finding stays
// probable, no bundle is written, and the report says it was not
// reproduced. The nightly gate reads verified findings only, so the run
// passes it; the PR gate judged these findings at probable (ADR 0021).
func TestZeroRunsStayProbable(t *testing.T) {
	tarpit := func(_ int, requests [][]byte) ([]sandbox.Exchange, error) {
		out := make([]sandbox.Exchange, len(requests))
		for i := range out {
			out[i] = sandbox.Exchange{Response: []byte("HTTP/1.1 200 OK\r\n\r\n[]"), Elapsed: 3100 * time.Millisecond}
		}
		return out, nil
	}
	code, out, fb, m := pocScan(t, sqlDelayPoC, tarpit)
	if code != exitcode.OK || fb.exchanges != 2*verify.DefaultRuns || m.pocCalls != 2 {
		t.Fatalf("exit %d, %d exchanges, %d PoC calls\n%s", code, fb.exchanges, m.pocCalls, out)
	}
	assertAllProbable(t)
	assertContains(t, "report.md", readState(t, "report.md"), []string{"0 verified in every run, 0 intermittent, 2 not reproduced"})
	if entries, err := os.ReadDir(filepath.Join(stateDir, bundleDir)); err == nil && len(entries) > 0 {
		t.Errorf("bundles written for a 0/5 PoC: %v", entries)
	}
}

// Protection (#25): the bundle holds no secret. The app answers with
// credentials of several kinds and the model's PoC sends one in a header;
// the bundle on disk keeps the runs, but every secret is a redaction
// marker, never its value.
func TestBundleHoldsNoSecret(t *testing.T) {
	secrets := []string{
		"ghp_" + "0123456789abcdefghijABCDEFGHIJ012345",
		"AKIA" + "Z7QXJ3K2M4N6P8R1",
		"xoxb-" + "123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx",
	}
	poc := map[string]any{}
	for k, v := range sqlDelayPoC {
		poc[k] = v
	}
	poc["sql_payload"] = map[string]any{
		"request": map[string]any{"method": "GET", "path": "/users?id=__CREEP_PAYLOAD__",
			"headers": []any{map[string]any{"name": "Authorization", "value": "token " + secrets[0]}}, "content_type": "", "body": ""},
		"context": "numeric", "technique": "delay",
	}
	body := "aws_access_key_id = " + secrets[1] + "\nslack_token: " + secrets[2] + "\n"
	code, out, _, _ := pocScan(t, poc, delayApp(repeatBool(true, 5), body))
	if code != exitcode.GateExceeded {
		t.Fatalf("exit %d\n%s", code, out)
	}
	f := sqliFinding(t)
	data, err := os.ReadFile(filepath.Join(stateDir, bundleName(f.ID)))
	if err != nil {
		t.Fatalf("no bundle: %v\n%s", err, out)
	}
	for _, s := range secrets {
		if bytes.Contains(data, []byte(s)) || strings.Contains(out, s) {
			t.Errorf("secret %.8s... in the bundle or output", s)
		}
	}
	var b verify.Bundle
	if err := json.Unmarshal(data, &b); err != nil || len(b.Runs) != verify.DefaultRuns || b.Rate != (verify.Rate{Verified: 5, Runs: 5}) {
		t.Fatalf("bundle %+v, %v", b.Rate, err)
	}
	step := b.Runs[0].Steps[1]
	if step.Withheld || !strings.Contains(step.Response, "aws_access_key_id") || !strings.Contains(step.Request, "pg_sleep") {
		t.Errorf("bundle step lost its text: %+v", step)
	}
	if b.Images.App != builtApp.Image || b.Images.Database != sandbox.DatabaseImage || b.Seed.SHA256 == "" || b.Port != 5000 {
		t.Errorf("bundle meta: %+v %+v port %d", b.Images, b.Seed, b.Port)
	}
}

// TestPoCStageStopsOnSandboxError: a sandbox error (here the network
// canary) ends the stage at once, verifies nothing, and counts the PoC as
// not run.
func TestPoCStageStopsOnSandboxError(t *testing.T) {
	fails := func(int, [][]byte) ([]sandbox.Exchange, error) { return nil, sandbox.ErrNetworkLeak }
	code, out, fb, _ := pocScan(t, sqlDelayPoC, fails)
	if code != exitcode.GateExceeded || fb.exchanges != 1 {
		t.Fatalf("exit %d, %d exchanges\n%s", code, fb.exchanges, out)
	}
	assertAllProbable(t)
	assertContains(t, "output", out, []string{"2 got no PoC run", "sandbox network reaches outside"})
}

// TestPoCStageStopsOnModelError: a PoC request the model link fails (a
// transport error, as a spent budget) ends the stage after that one call;
// nothing is verified and no runner starts.
func TestPoCStageStopsOnModelError(t *testing.T) {
	fb := &fakeBuilder{app: builtApp, port: 5000, exchange: delayApp(repeatBool(true, 10), "")}
	m := &fakeModel{verdict: sqliVulnerable, fail: map[string]error{"poc": errors.New("connection reset")}}
	opened := 0
	files := map[string]string{"app.py": "@flask", "migrations/1_init.sql": "CREATE TABLE users (id int);\n"}
	code, stdout, stderr := runScanWith(withBuilder(fakeDeps(m, calibrate.TierM), fb, nil, &opened), "--config", scanRepo(t, files, sandboxOn), "scan", "--mode", "nightly")
	out := stdout + stderr
	if code != exitcode.GateExceeded || m.pocCalls == 0 || fb.exchanges != 0 {
		t.Fatalf("exit %d, %d PoC calls, %d exchanges\n%s", code, m.pocCalls, fb.exchanges, out)
	}
	assertAllProbable(t)
	assertContains(t, "output", out, []string{"2 got no PoC run"})
}

// TestInvalidPoCSkipsOnly: output that is not a valid PoC skips that
// finding and the stage goes on to the next; only a model link error
// stops it (TestPoCStageStopsOnModelError).
func TestInvalidPoCSkipsOnly(t *testing.T) {
	invalid := map[string]any{"template": "shell", "http_request": nil, "http_sequence": nil, "sql_payload": nil, "path_payload": nil}
	code, out, fb, m := pocScan(t, invalid, delayApp(repeatBool(true, 10), ""))
	if code != exitcode.GateExceeded || fb.exchanges != 0 {
		t.Fatalf("exit %d, %d PoC calls, %d exchanges\n%s", code, m.pocCalls, fb.exchanges, out)
	}
	assertAllProbable(t)
	assertContains(t, "output", out, []string{"2 got no PoC run", "no PoC run for sink-1: poc request: model output invalid", "no PoC run for sink-2: poc request: model output invalid"})
}

// TestPoCStageBounds: a scan tries at most maxPoCs PoCs, the rest counted
// not run, and a stage whose context ended (the scan deadline, Ctrl+C)
// runs none.
func TestPoCStageBounds(t *testing.T) {
	for _, n := range []int{0, 1, maxPoCs, maxPoCs + 1, 3 * maxPoCs} {
		todo, skipped := pocBatch(make([]int, n))
		if len(todo) != min(n, maxPoCs) || skipped != n-len(todo) {
			t.Errorf("%d candidates: try %d, skip %d", n, len(todo), skipped)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sum := (pocStage{}).run(ctx, make([]int, maxPoCs+2)); sum != (report.PoCSummary{NotRun: maxPoCs + 2}) {
		t.Errorf("ended stage: %+v", sum)
	}
}

// TestMaxRunsMatchReport keeps report's copy of verify.MaxRuns in step.
func TestMaxRunsMatchReport(t *testing.T) {
	f := report.Finding{ID: "sink-1", Class: "sqli", Status: report.StatusVerified, Path: "a.py", Line: 1,
		PoC: report.PoCRate{Verified: verify.MaxRuns, Runs: verify.MaxRuns}}
	if _, err := report.New(report.Input{Findings: []report.Finding{f}}); err != nil {
		t.Errorf("report refuses verify.MaxRuns: %v", err)
	}
	f.PoC = report.PoCRate{Verified: 1, Runs: verify.MaxRuns + 1}
	if _, err := report.New(report.Input{Findings: []report.Finding{f}}); err == nil {
		t.Error("report accepts more than verify.MaxRuns")
	}
}
