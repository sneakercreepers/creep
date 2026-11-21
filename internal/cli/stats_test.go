package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

// tickingClock advances one second per reading, so each phase takes 1s.
func tickingClock() func() time.Time {
	t := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

var requestsLine = regexp.MustCompile(`model requests: (\d+) \((\d+) sent, (\d+) from cache, (\d+) failed; cache hit rate ([0-9n/a%]+)\)`)

// Acceptance (#15): --stats prints per-phase times, requests, cache hits
// and tokens. A recorded run sends every request; its replay serves all of
// them from the cache, spends no tokens and has a 100% hit rate.
func TestScanStatsRecordAndReplay(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	tests := []struct {
		name     string
		mode     string
		wantHit  string
		wantSent bool
	}{
		{"record", "--record", "0%", true},
		{"replay", "--replay", "100%", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := usageDeps(&fakeModel{})
			deps.now = tickingClock()
			_, out, errOut := runScanWith(deps, "scan", tt.mode, "--stats", "--price-in", "3", "--price-out", "15", "--config", cfg)
			if !strings.Contains(out, "phases: walk 1s, calibrate 1s, discover 1s, plan 1s, read 1s, report 1s\n") {
				t.Fatalf("phases:\n%s\n%s", out, errOut)
			}
			m := requestsLine.FindStringSubmatch(out)
			if m == nil || m[1] == "0" || m[4] != "0" || m[5] != tt.wantHit {
				t.Fatalf("requests line %q:\n%s", m, out)
			}
			sent, in, _ := statsTotals(t, out)
			if (sent > 0) != tt.wantSent || (in > 0) != tt.wantSent {
				t.Fatalf("sent %d, tokens in %d:\n%s", sent, in, out)
			}
			if !strings.Contains(out, "by purpose: discover 1, reader ") || !strings.Contains(out, "cost: 0.") {
				t.Fatalf("purpose or cost missing:\n%s", out)
			}
		})
	}
}

// With --format json stdout is the report alone; the stats go to stderr.
// Failed requests are counted, and the output holds no repository text.
func TestScanStatsFormatAndFailures(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"zzname.py": "@flask"}, "")
	m := &fakeModel{fail: map[string]error{"ssrf": errors.New("down")}}
	_, out, errOut := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--format", "json", "--stats", "--config", cfg)
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("stdout is not only the report: %v\n%s", err, out)
	}
	stats := errOut[strings.Index(errOut, "stats:"):]
	r := requestsLine.FindStringSubmatch(stats)
	if r == nil || r[4] == "0" {
		t.Fatalf("failed requests not counted:\n%s", errOut)
	}
	if strings.Contains(stats, "zz") || !strings.Contains(stats, "cost: not computed") {
		t.Fatalf("stats:\n%s", stats)
	}
}

// Without --stats nothing is added to the scan's output.
func TestScanWithoutStats(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	_, out, _ := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--config", cfg)
	if strings.Contains(out, "stats:") {
		t.Fatalf("stats printed without --stats:\n%s", out)
	}
}

func TestPricingCost(t *testing.T) {
	tests := []struct {
		name    string
		price   pricing
		in, out int
		want    string
	}{
		{"unset", pricing{}, 1000, 10, "not computed: set --price-in"},
		{"command contract", pricing{in: 3, out: 15, quota: true}, 1000, 10, "subscription quota"},
		{"priced", pricing{in: 3, out: 15}, 1_000_000, 100_000, "4.5000 (at 3 in, 15 out per 1M tokens)"},
		{"output only", pricing{out: 10}, 5, 1_000_000, "10.0000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.price.cost(tt.in, tt.out); !strings.Contains(got, tt.want) {
				t.Fatalf("cost = %q, want %q", got, tt.want)
			}
		})
	}
}

// Every request lands in exactly one bucket: sent, cached or failed, and
// only sent replies add to the tokens spent.
func TestRunStatsCounting(t *testing.T) {
	usage := func([]byte) (gateway.Usage, bool) { return gateway.Usage{InputTokens: 10, OutputTokens: 2}, true }
	ok := func(context.Context, gateway.Call) (*gateway.Reply, error) { return &gateway.Reply{Status: 200}, nil }
	fail := func(context.Context, gateway.Call) (*gateway.Reply, error) { return nil, errors.New("down") }
	st := newRunStats(nil)
	sent := st.countRequests(st.countSent(ok))
	cached := st.countRequests(ok) // a cache hit never reaches the transport
	failed := st.countRequests(st.countSent(fail))
	call := gateway.Call{Purpose: "reader", Usage: usage}
	for _, send := range []func(context.Context, gateway.Call) (*gateway.Reply, error){sent, sent, cached, failed} {
		_, _ = send(context.Background(), call)
	}
	if st.requests != 4 || st.sent != 3 || st.cached != 1 || st.failed != 1 {
		t.Fatalf("requests %d sent %d cached %d failed %d", st.requests, st.sent, st.cached, st.failed)
	}
	if st.usage.InputTokens != 20 || st.cacheUse.InputTokens != 10 {
		t.Fatalf("usage %+v, cache %+v", st.usage, st.cacheUse)
	}
	if percent(1, 4) != "25%" || percent(0, 0) != "n/a" {
		t.Fatal("percent")
	}
}

// Regression (#222 L1): the gateway and the run-state cache return a 429 or
// 500 reply with no error, and it counts as failed, not as a sent reply with
// no token count; a 200 reply adds its tokens.
func TestRunStatsCountsHTTPErrors(t *testing.T) {
	usage := func([]byte) (gateway.Usage, bool) { return gateway.Usage{InputTokens: 10, OutputTokens: 2}, true }
	noUsage := func([]byte) (gateway.Usage, bool) { return gateway.Usage{}, false }
	tests := []struct {
		name      string
		reply     *gateway.Reply
		err       error
		wantFail  int
		wantNoUse int
		wantIn    int
	}{
		{"200", &gateway.Reply{Status: 200}, nil, 0, 0, 10},
		{"429", &gateway.Reply{Status: 429}, nil, 1, 0, 0},
		{"500", &gateway.Reply{Status: 500}, nil, 1, 0, 0},
		{"transport error", nil, errors.New("connection reset"), 1, 0, 0},
		{"no reply and no error", nil, nil, 1, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := newRunStats(nil)
			send := st.countRequests(st.countSent(func(context.Context, gateway.Call) (*gateway.Reply, error) { return tt.reply, tt.err }))
			_, _ = send(context.Background(), gateway.Call{Purpose: "reader", Usage: usage})
			if st.requests != 1 || st.sent != 1 || st.failed != tt.wantFail || st.noUsage != tt.wantNoUse || st.usage.InputTokens != tt.wantIn {
				t.Fatalf("requests %d sent %d failed %d no usage %d tokens in %d", st.requests, st.sent, st.failed, st.noUsage, st.usage.InputTokens)
			}
		})
	}
	// A 200 reply that reports no count is the only "no count" reply.
	st := newRunStats(nil)
	ok := func(context.Context, gateway.Call) (*gateway.Reply, error) { return &gateway.Reply{Status: 200}, nil }
	_, _ = st.countRequests(st.countSent(ok))(context.Background(), gateway.Call{Usage: noUsage})
	if st.failed != 0 || st.noUsage != 1 {
		t.Fatalf("failed %d, no usage %d", st.failed, st.noUsage)
	}
}

// Regression (#222 I1, I2): a scan that fails after it reached the model,
// with exit 3 (a model error) or 2 (an error that carries its own code),
// still prints --stats on stderr, and the 500 replies it got count as
// failed; without --stats nothing is added.
func TestScanStatsOnFailure(t *testing.T) {
	tests := []struct {
		name     string
		stats    bool
		coded    bool
		wantCode int
	}{
		{"model error", true, false, exitcode.ModelOrSandbox},
		{"error with its own code", true, true, exitcode.ConfigError},
		{"without --stats", false, false, exitcode.ModelOrSandbox},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			deps := fakeDeps(&fakeModel{}, calibrate.TierM)
			deps.connect = func(*config.Resolved, string, io.Writer) (modelLink, error) {
				return modelLink{send: serverError, close: func() error { return nil }}, nil
			}
			deps.calibrate = sendingCalibration(tt.coded)
			args := []string{"scan", "--config", cfg}
			if tt.stats {
				args = append(args, "--stats")
			}
			code, out, errOut := runScanWith(deps, args...)
			if code != tt.wantCode || strings.Contains(out, "stats:") || strings.Contains(errOut, "stats:") != tt.stats {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out, errOut)
			}
			if !tt.stats {
				return
			}
			r := requestsLine.FindStringSubmatch(errOut)
			if r == nil || r[1] == "0" || r[2] != r[1] || r[4] != r[1] || !strings.Contains(errOut, "by purpose: calibration ") {
				t.Fatalf("every sent request must count as failed:\n%s", errOut)
			}
		})
	}
}

func serverError(context.Context, gateway.Call) (*gateway.Reply, error) {
	return &gateway.Reply{ID: "fake", Status: 500, Body: []byte(`{"error":"down"}`)}, nil
}

// codedError carries its own exit code, as a consent error does.
type codedError struct{ error }

func (codedError) ExitCode() int { return exitcode.ConfigError }

// sendingCalibration stands in for calibration that reaches the model and
// fails: one request through the scan's model, then its error, or a coded
// one.
func sendingCalibration(coded bool) func(context.Context, calibrate.CacheOptions) (calibrate.Calibration, error) {
	return func(ctx context.Context, opts calibrate.CacheOptions) (calibrate.Calibration, error) {
		_, err := models.Complete[map[string]any](ctx, opts.Model, models.Request{
			Purpose: "calibration", System: "s", Prompt: "p",
			Schema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		})
		if err == nil {
			return calibrate.Calibration{}, errors.New("fake calibration: the model answered")
		}
		if coded {
			return calibrate.Calibration{}, codedError{err}
		}
		return calibrate.Calibration{}, err
	}
}
