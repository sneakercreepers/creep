package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/report"
)

// sampledModel answers each --stability sample with its own fake model:
// sample k's calls carry the purpose suffix -s<k> (sampleSend).
type sampledModel struct {
	samples  []*fakeModel
	purposes map[string]int
	limit    int // refuse calls past this many with the budget error; 0 is none
	calls    int
}

func newSampledModel(verdicts ...string) *sampledModel {
	m := &sampledModel{purposes: map[string]int{}}
	for _, v := range verdicts {
		m.samples = append(m.samples, &fakeModel{verdict: map[string]string{"sql_injection": v}})
	}
	return m
}

func (m *sampledModel) send(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
	if m.limit > 0 && m.calls >= m.limit {
		return nil, fmt.Errorf("send: %w", gateway.ErrBudgetExhausted)
	}
	m.calls++
	m.purposes[c.Purpose]++
	k := 1
	if _, suffix, ok := strings.Cut(c.Purpose, "-s"); ok {
		if _, err := fmt.Sscanf(suffix, "%d", &k); err != nil {
			return nil, err
		}
	}
	if k < 1 || k > len(m.samples) {
		return nil, fmt.Errorf("fake: no sample %d (purpose %q)", k, c.Purpose)
	}
	return m.samples[k-1].send(ctx, c)
}

// stabilityCache stands in for the user cache: calibration reads the
// stability record the last recordStability wrote, as RunCached does.
type stabilityCache struct {
	record  map[calibrate.Class]calibrate.ClassStability
	records int
}

func sampledDeps(m *sampledModel, cache *stabilityCache) scanDeps {
	fixed := fixedCalibration(calibrate.TierM, nil)
	return scanDeps{
		connect: func(*config.Resolved, string, io.Writer) (modelLink, error) {
			return modelLink{send: m.send, close: func() error { return nil }}, nil
		},
		calibrate: func(ctx context.Context, opts calibrate.CacheOptions) (calibrate.Calibration, error) {
			c, err := fixed(ctx, opts)
			c.Stability = cache.record
			return c, err
		},
		recordStability: func(opts calibrate.CacheOptions, seen map[calibrate.Class]calibrate.ClassStability) (map[calibrate.Class]calibrate.ClassStability, error) {
			if opts.Model == nil || opts.MaxAge <= 0 || opts.Seed != calibrationSeed {
				return nil, fmt.Errorf("fake record: incomplete options %+v", opts)
			}
			cache.records++
			rec := map[calibrate.Class]calibrate.ClassStability{}
			for class, c := range cache.record {
				rec[class] = c
			}
			for class, c := range seen {
				sum := rec[class]
				sum.Findings, sum.Unstable = sum.Findings+c.Findings, sum.Unstable+c.Unstable
				rec[class] = sum
			}
			cache.record = rec
			return rec, nil
		},
	}
}

// sqliFindings are the report's SQL injection findings: the Flask app has
// two sinks, which every sample's discovery names (the tripwire does).
func sqliFindings(t *testing.T) []report.Finding {
	t.Helper()
	var out []report.Finding
	for _, f := range lastReport(t).Findings {
		if f.Class == "sqli" {
			out = append(out, f)
		}
	}
	if len(out) != 2 {
		t.Fatalf("%d sqli findings, want the Flask app's two", len(out))
	}
	return out
}

// #37 acceptance: each sample asks the model again (its own label, so its
// own call), a finding keeps the riskiest answer of its samples, and a
// finding seen in fewer than N samples is labeled unstable discovery in
// the text summary and the report.
func TestStabilityLabelsFindings(t *testing.T) {
	tests := []struct {
		name      string
		verdicts  []string
		status    report.Status
		reason    string
		stability *report.Stability
		code      int
	}{
		{"seen in every run", []string{"vulnerable", "vulnerable", "vulnerable"}, report.StatusProbable, "", report.NewStability(3, 3), exitcode.GateExceeded},
		{"seen in two of three", []string{"vulnerable", "not_vulnerable", "vulnerable"}, report.StatusProbable, "", report.NewStability(2, 3), exitcode.GateExceeded},
		{"seen only by a rerun", []string{"not_vulnerable", "not_vulnerable", "vulnerable"}, report.StatusProbable, "", report.NewStability(1, 3), exitcode.GateExceeded},
		{"vulnerable beats inconclusive", []string{"inconclusive", "vulnerable"}, report.StatusProbable, "", report.NewStability(1, 2), exitcode.GateExceeded},
		{"discarded in every run", []string{"not_vulnerable", "not_vulnerable"}, report.StatusDiscarded, "", nil, exitcode.OK},
		{"inconclusive beats discarded", []string{"not_vulnerable", "inconclusive"}, report.StatusNotEvaluated, reasonInconclusive, nil, exitcode.Incomplete},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			m := newSampledModel(tt.verdicts...)
			n := len(tt.verdicts)
			code, out, errOut := runScanWith(sampledDeps(m, &stabilityCache{}), "scan", "--stability", fmt.Sprint(n), "--config", cfg)
			if code != tt.code {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, tt.code, out, errOut)
			}
			for _, f := range sqliFindings(t) {
				if f.Status != tt.status || f.Reason != tt.reason || fmt.Sprint(f.Stability) != fmt.Sprint(tt.stability) {
					t.Errorf("finding %s: %s %q %+v, want %s %q %+v", f.ID, f.Status, f.Reason, f.Stability, tt.status, tt.reason, tt.stability)
				}
			}
			if label := tt.stability.Text(); label != "" && !strings.Contains(out, label) {
				t.Errorf("summary lacks %q:\n%s", label, out)
			}
			for _, purpose := range []string{"discover", "reader"} {
				for k := 2; k <= n; k++ {
					label := fmt.Sprintf("%s-s%d", purpose, k)
					if m.purposes[label] != m.purposes[purpose] || m.purposes[purpose] == 0 {
						t.Errorf("%s: %d calls, %s: %d; every sample must make every call", purpose, m.purposes[purpose], label, m.purposes[label])
					}
				}
			}
			if !strings.Contains(errOut, fmt.Sprintf("whole source files %d times (--stability)", n)) {
				t.Errorf("the scan-start notice does not say discovery runs %d times:\n%s", n, errOut)
			}
		})
	}
}

// statusRisk orders a finding's status by the risk it reports.
func statusRisk(s report.Status) int {
	switch s {
	case report.StatusVerified:
		return 3
	case report.StatusProbable:
		return 2
	case report.StatusDiscarded:
		return 0
	}
	return 1
}

// lowered lists every finding of before that after drops or reports at a
// lower risk.
func lowered(before, after []report.Finding) []string {
	var out []string
	for _, b := range before {
		i := slices.IndexFunc(after, func(a report.Finding) bool { return a.ID == b.ID })
		switch {
		case i < 0:
			out = append(out, b.ID+" dropped")
		case statusRisk(after[i].Status) < statusRisk(b.Status):
			out = append(out, fmt.Sprintf("%s lowered from %s to %s", b.ID, b.Status, after[i].Status))
		}
	}
	return out
}

// Protection (#37, ADR 0024): stability is union only. Whatever the reruns
// answer, a --stability scan lists every finding a one-sample scan with
// the first sample's answers lists, none at a lower status, and its exit
// code is never more lenient. The broken cases show the check catching a
// dropped and a lowered finding.
func TestStabilityNeverLowersRisk(t *testing.T) {
	answers := []string{"vulnerable", "not_vulnerable", "inconclusive", "invalid"}
	for _, first := range answers {
		for _, rerun := range answers {
			t.Run(first+"_then_"+rerun, func(t *testing.T) {
				cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
				one := newSampledModel(first)
				code1, out, errOut := runScanWith(sampledDeps(one, &stabilityCache{}), "scan", "--config", cfg)
				if code1 == exitcode.ConfigError {
					t.Fatalf("one sample: exit %d\n%s\n%s", code1, out, errOut)
				}
				before := lastReport(t).Findings
				two := newSampledModel(first, rerun)
				code2, out, errOut := runScanWith(sampledDeps(two, &stabilityCache{}), "scan", "--stability", "2", "--config", cfg)
				after := lastReport(t).Findings
				if problems := lowered(before, after); len(problems) > 0 || len(after) != len(before) {
					t.Fatalf("stability lowered the result: %v (%d findings, want %d)\n%s\n%s", problems, len(after), len(before), out, errOut)
				}
				if code1 != exitcode.OK && code2 == exitcode.OK {
					t.Fatalf("exit %d with one sample but 0 with two", code1)
				}
			})
		}
	}
	probable := report.Finding{ID: "sink-1", Status: report.StatusProbable}
	if len(lowered([]report.Finding{probable}, nil)) != 1 {
		t.Error("the check missed a dropped finding")
	}
	discarded := probable
	discarded.Status = report.StatusDiscarded
	if len(lowered([]report.Finding{probable}, []report.Finding{discarded})) != 1 {
		t.Error("the check missed a lowered finding")
	}
}

// #37 acceptance: stability data never changes replay determinism. A
// recorded --stability run, whose samples answer differently, replays to
// the same summary and byte-identical reports with no model call; the
// replay writes no stability record, so what later scans read is unchanged.
func TestStabilityReplayIsDeterministic(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	cache := &stabilityCache{}
	recorder := newSampledModel("vulnerable", "not_vulnerable", "vulnerable")
	code, recorded, errOut := runScanWith(sampledDeps(recorder, cache), "scan", "--stability", "3", "--record", "--config", cfg)
	if code != exitcode.GateExceeded || !strings.Contains(recorded, "unstable discovery: seen in 2 of 3 runs") {
		t.Fatalf("record: exit %d\n%s\n%s", code, recorded, errOut)
	}
	if cache.records != 1 || cache.record[calibrate.ClassSQLi] != (calibrate.ClassStability{Findings: 2, Unstable: 2}) {
		t.Fatalf("record wrote %d stability records: %+v", cache.records, cache.record)
	}
	reports := readReports(t)
	// Answers that differ from the recording: a call would change the output.
	offline := newSampledModel("not_vulnerable", "not_vulnerable", "not_vulnerable")
	for range 2 {
		code, replayed, errOut := runScanWith(sampledDeps(offline, cache), "scan", "--stability", "3", "--replay", "--config", cfg)
		if code != exitcode.GateExceeded || replayed != recorded || offline.calls != 0 {
			t.Fatalf("replay: exit %d after %d calls\nrecorded:\n%s\nreplayed:\n%s\n%s", code, offline.calls, recorded, replayed, errOut)
		}
		for name, data := range readReports(t) {
			if data != reports[name] {
				t.Errorf("replayed %s differs from the recorded one", name)
			}
		}
		if cache.records != 1 {
			t.Fatalf("replay wrote a stability record (%d writes)", cache.records)
		}
	}
}

func readReports(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range []string{"report.json", "report.sarif", "report.md"} {
		data, err := os.ReadFile(filepath.Join(stateDir, name))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = string(data)
	}
	return out
}

// --stability stays inside budget.max_calls: the reruns' calls count like
// any other, so a budget that fits one sample ends a three-sample run
// incomplete (exit 4), never clean, and `creep estimate` counts every
// sample's calls and warns before the run.
func TestStabilityRespectsBudget(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	one := newSampledModel("not_vulnerable")
	if code, out, errOut := runScanWith(sampledDeps(one, &stabilityCache{}), "scan", "--config", cfg); code != exitcode.OK {
		t.Fatalf("one sample: exit %d\n%s\n%s", code, out, errOut)
	}
	three := newSampledModel("not_vulnerable", "not_vulnerable", "not_vulnerable")
	three.limit = one.calls
	code, out, errOut := runScanWith(sampledDeps(three, &stabilityCache{}), "scan", "--stability", "3", "--config", cfg)
	if code != exitcode.Incomplete || !strings.Contains(out, "INCOMPLETE RUN (reason budget)") {
		t.Fatalf("a budget for one sample: exit %d, want 4 (budget)\n%s\n%s", code, out, errOut)
	}

	budget := withBudget(t, cfg, one.calls)
	_, plain, _ := runScanWith(offlineDeps(t, true), "estimate", "--config", budget)
	code, est, errOut := runScanWith(offlineDeps(t, true), "estimate", "--stability", "3", "--config", budget)
	if code != exitcode.OK {
		t.Fatalf("estimate: exit %d\n%s", code, errOut)
	}
	calls1, _, _ := estimateRow(t, plain, "M *")
	calls3, _, _ := estimateRow(t, est, "M *")
	if calls3 != 3*calls1 || strings.Contains(plain, "over budget.max_calls") {
		t.Fatalf("estimate counts %d calls for three samples, %d for one; want three times as many, the warning only for three\n%s\n%s", calls3, calls1, plain, est)
	}
	for _, want := range []string{"stability: 3 runs", "uncached calls, over budget.max_calls"} {
		if !strings.Contains(est, want) {
			t.Errorf("estimate lacks %q:\n%s", want, est)
		}
	}
}

// --stability takes 1 to maxStability runs, and only scan and estimate
// take it; anything else is a usage error before any model call.
func TestStabilityFlag(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"scan", "--stability", "0"}, "--stability 0: want 1 to 5 runs"},
		{[]string{"scan", "--stability", "6"}, "--stability 6: want 1 to 5 runs"},
		{[]string{"scan", "--stability", "-1"}, "--stability -1: want 1 to 5 runs"},
		{[]string{"estimate", "--stability", "6"}, "--stability 6: want 1 to 5 runs"},
		{[]string{"scan", "--stability", "two"}, "invalid value"},
		{[]string{"scan", "--stability", "1.5"}, "invalid value"},
		{[]string{"why", "sink-1", "--stability", "2"}, "--stability changes only scan and estimate, not why"},
		{[]string{"doctor", "--stability", "1"}, "--stability changes only scan and estimate, not doctor"},
	}
	for _, tt := range tests {
		code, _, errOut := runScanWith(noModelDeps, tt.args...)
		if code != exitcode.ConfigError || !strings.Contains(errOut, tt.want) {
			t.Errorf("%v: exit %d, stderr %q; want 2 and %q", tt.args, code, errOut, tt.want)
		}
	}
	if discover.MaxSamples != report.MaxStabilityRuns {
		t.Errorf("discover.MaxSamples %d, report.MaxStabilityRuns %d: keep them equal", discover.MaxSamples, report.MaxStabilityRuns)
	}
}

// Each hypothesis costs one reader call per sample, so the planner plans
// only what the budget pays for at N samples (ADR 0024); out-of-range
// sample counts never shrink the step cost below one call.
func TestPlanBudgetCountsSamples(t *testing.T) {
	one := planBudget(1_000_000, reader.TierM, 1).StepTokens
	for _, tt := range []struct{ samples, want int }{{0, 1}, {1, 1}, {3, 3}, {5, 5}, {9, 5}} {
		if got := planBudget(1_000_000, reader.TierM, tt.samples).StepTokens; got != one*uint32(tt.want) { //nolint:gosec // G115: at most 5
			t.Errorf("%d samples: step %d tokens, want %d", tt.samples, got, one*uint32(tt.want)) //nolint:gosec // G115: at most 5
		}
	}
}

// labelStability counts a sample only when its discovery named the sink
// and its reader answered vulnerable, labels only probable findings that
// every sample answered, and never changes a status.
func TestLabelStability(t *testing.T) {
	sinks := []discover.Sink{{SeenBy: 0b111}, {SeenBy: 0b011}, {SeenBy: 0b111}, {SeenBy: 0b001}}
	findings := []report.Finding{
		{ID: "sink-1", Status: report.StatusProbable},
		{ID: "sink-2", Status: report.StatusProbable},
		{ID: "sink-3", Status: report.StatusDiscarded},
		{ID: "sink-4", Status: report.StatusProbable}, // a sample stopped: no votes
	}
	labelStability(findings, sinks, map[int]uint8{0: 0b110, 1: 0b110, 2: 0}, 3)
	want := []*report.Stability{report.NewStability(2, 3), report.NewStability(1, 3), nil, nil}
	for i, f := range findings {
		if fmt.Sprint(f.Stability) != fmt.Sprint(want[i]) || (i == 2) != (f.Status == report.StatusDiscarded) {
			t.Errorf("%s: %s %+v, want %+v", f.ID, f.Status, f.Stability, want[i])
		}
	}
	one := []report.Finding{{ID: "sink-1", Status: report.StatusProbable}}
	labelStability(one, sinks, map[int]uint8{0: 1}, 1)
	if one[0].Stability != nil {
		t.Error("a one-sample run labeled a finding")
	}
}

// withBudget copies the model config at cfg with budget.max_calls set.
func withBudget(t *testing.T, cfg string, calls int) string {
	t.Helper()
	data, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "creep.yaml")
	data = fmt.Appendf(data, "budget:\n  max_calls: %d\n", calls)
	// G703: out is in the test's own t.TempDir().
	if err := os.WriteFile(out, data, 0o600); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	return out
}
