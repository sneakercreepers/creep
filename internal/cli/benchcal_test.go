package cli

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/bench"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
)

// alwaysSafeCalibration answers every calibration task "safe" and every
// probe wrongly; any other call goes to next.
func alwaysSafeCalibration(next func(context.Context, gateway.Call) (*gateway.Reply, error)) (func(context.Context, gateway.Call) (*gateway.Reply, error), *int) {
	calls := new(int)
	return func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
		if !isCalibration(c) {
			return next(ctx, c)
		}
		*calls++
		answer := map[string]any{"vulnerable": false, "class": "none", "line": 0}
		switch c.Purpose {
		case "calibrate-tool":
			answer = map[string]any{"tool": "list_dir", "argument": "nowhere"}
		case "calibrate-context":
			answer = map[string]any{"value": "wrong"}
		}
		body, err := chatReply(answer)
		return &gateway.Reply{ID: "fake", Status: 200, Body: body}, err
	}, calls
}

// bench --recalibrate runs one live calibration first and publishes its
// cost (calls, tokens, time) with the tier and fitness it measured
// (#363); the fixture keeps corpus replies only, and --replay refuses it.
func TestBenchRecalibrateMeasuresCost(t *testing.T) {
	cfg := scanRepo(t, nil, "")
	cases, err := bench.Corpus()
	if err != nil {
		t.Fatal(err)
	}
	oracle := &benchOracle{cases: cases}
	send, calCalls := alwaysSafeCalibration(oracle.send)
	deps := scanDeps{connect: func(*config.Resolved, string, io.Writer) (modelLink, error) {
		return modelLink{send: send, close: func() error { return nil }}, nil
	}}
	code, out, stderr := runScanWith(deps, "bench", "--record", "--recalibrate", "--config", cfg, "--format", "json")
	if code != exitcode.OK {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var res bench.Results
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	// 100 tasks, 3 tool probes, and the first context probe it misses.
	want := bench.CalibrationCost{Calls: 104, InputTokens: 0, OutputTokens: res.Calibration.OutputTokens, Tier: "S", Fit: false, Unfit: "below_chance"}
	if res.Calibration == nil || *calCalls != 104 || res.Calibration.OutputTokens == 0 {
		t.Fatalf("calibration %+v after %d calls", res.Calibration, *calCalls)
	}
	got := *res.Calibration
	got.Seconds = 0
	if got != want {
		t.Errorf("calibration %+v, want %+v", got, want)
	}
	if fix := recordedBenchFixture(t); len(fix.Replies) != oracle.calls {
		t.Errorf("fixture holds %d replies for %d corpus calls", len(fix.Replies), oracle.calls)
	}
	code, _, stderr = runScanWith(noModelDeps, "bench", "--replay", "--recalibrate")
	if code != exitcode.ConfigError || !strings.Contains(stderr, "--replay") {
		t.Errorf("--replay --recalibrate: exit %d, stderr %q", code, stderr)
	}
}
