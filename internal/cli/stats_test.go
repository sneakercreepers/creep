package cli

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/gateway"
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
