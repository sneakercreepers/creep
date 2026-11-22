package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/baseline"
	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
)

// baselineToday is the date the baseline tests run on.
var baselineToday = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

// baselineDeps is a scan whose reader finds the Flask app's SQL injection.
func baselineDeps(m *fakeModel, today time.Time) scanDeps {
	deps := fakeDeps(m, calibrate.TierM)
	deps.date = func() time.Time { return today }
	return deps
}

func vulnerableSQL() *fakeModel {
	return &fakeModel{verdict: map[string]string{"sql_injection": "vulnerable"}}
}

// lastReport reads the scan's JSON report as `creep why` does.
func lastReport(t *testing.T) *report.Report {
	t.Helper()
	rep, err := readLastReport()
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// probableSQLi is the report's probable SQL injections (the Flask app
// has two sinks), each with its fingerprint.
func probableSQLi(t *testing.T, rep *report.Report) []report.Finding {
	t.Helper()
	var out []report.Finding
	for _, f := range rep.Findings {
		if f.Class == "sqli" && f.Status == report.StatusProbable {
			if f.Fingerprint == "" {
				t.Fatalf("probable finding %s has no fingerprint", f.ID)
			}
			out = append(out, f)
		}
	}
	if len(out) != 2 || out[0].Fingerprint == out[1].Fingerprint {
		t.Fatalf("want two probable sqli findings with distinct fingerprints: %+v", rep.Findings)
	}
	return out
}

func fingerprints(fs []report.Finding) string {
	return fs[0].Fingerprint + " " + fs[1].Fingerprint
}

// Acceptance (#27), end to end: an accepted risk keeps its finding from the
// gate, still listed in every format; the fingerprint survives code added
// above the sink; and the finding is new again on the day it expires.
func TestScanAcceptCycle(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	deps := baselineDeps(vulnerableSQL(), baselineToday)
	if code, _, stderr := runScanWith(deps, "scan", "--config", cfg); code != exitcode.GateExceeded {
		t.Fatalf("first scan exit %d, want 1: %s", code, stderr)
	}
	found := probableSQLi(t, lastReport(t))
	for _, f := range found {
		code, stdout, stderr := runScanWith(deps, "accept", f.ID, "--expires", "30d", "--reason", "admin-only endpoint, fix tracked")
		if code != exitcode.OK || !strings.Contains(stdout, "until 2026-12-21 in creep-baseline.json") {
			t.Fatalf("accept exit %d: %s%s", code, stdout, stderr)
		}
	}

	code, stdout, stderr := runScanWith(deps, "scan", "--config", cfg, "--baseline", defaultBaselineFile)
	if code != exitcode.OK {
		t.Fatalf("scan with the accepted risk exit %d, want 0: %s%s", code, stdout, stderr)
	}
	assertContains(t, "stdout", stdout, []string{
		found[0].ID + "  probable  sqli", "suppressed: accepted risk until 2026-12-21: admin-only endpoint, fix tracked",
		"baseline: 2 findings suppressed (0 baseline, 2 accepted risks)",
	})
	assertSuppressedInReports(t, found[0].ID)

	// Unrelated code above the sink moves every line down.
	app, err := os.ReadFile("app.py")
	if err != nil {
		t.Fatal(err)
	}
	moved := "import logging\n\nlog = logging.getLogger(__name__)\n\n\ndef helper():\n    return 1\n\n\n" + string(app)
	// G703: a fixed name in the test's t.TempDir().
	if err := os.WriteFile("app.py", []byte(moved), 0o600); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	code, stdout, _ = runScanWith(deps, "scan", "--config", cfg, "--baseline", defaultBaselineFile)
	if code != exitcode.OK || fingerprints(probableSQLi(t, lastReport(t))) != fingerprints(found) {
		t.Fatalf("after a code move: exit %d, fingerprint changed: %s", code, stdout)
	}

	expired := baselineDeps(vulnerableSQL(), baselineToday.AddDate(0, 0, 30))
	code, stdout, _ = runScanWith(expired, "scan", "--config", cfg, "--baseline", defaultBaselineFile)
	if code != exitcode.GateExceeded || strings.Contains(stdout, "suppressed: accepted") || !strings.Contains(stdout, "2 expired entries suppress nothing") {
		t.Fatalf("on the expiry day: exit %d, want 1 with the finding new:\n%s", code, stdout)
	}
}

// assertSuppressedInReports checks each written report lists id and its
// suppression: nothing a baseline hides disappears.
func assertSuppressedInReports(t *testing.T, id string) {
	t.Helper()
	f, ok := lastReport(t).Finding(id)
	if !ok || f.Suppression == nil || f.Suppression.Kind != report.SuppressAccepted {
		t.Errorf("JSON finding %s: %+v", id, f)
	}
	for name, want := range map[string]string{"report.md": "## Suppressed", "report.sarif": `"suppressions"`} {
		data, err := os.ReadFile(filepath.Join(stateDir, name))
		if err != nil || !bytes.Contains(data, []byte(want)) || !bytes.Contains(data, []byte(id)) {
			t.Errorf("%s lacks %q or %s: %v", name, want, id, err)
		}
	}
}

// --baseline-write takes a baseline from a complete run; the next scan
// gates only on new findings. An incomplete run writes nothing.
func TestScanBaselineWrite(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	deps := baselineDeps(vulnerableSQL(), baselineToday)
	code, _, stderr := runScanWith(deps, "scan", "--config", cfg, "--baseline", "b.json", "--baseline-write")
	if code != exitcode.GateExceeded || !strings.Contains(stderr, "baseline: wrote 2 entries to b.json (2 baseline, expiring in 90 days") {
		t.Fatalf("write exit %d: %s", code, stderr)
	}
	if code, stdout, _ := runScanWith(deps, "scan", "--config", cfg, "--baseline", "b.json"); code != exitcode.OK ||
		!strings.Contains(stdout, "suppressed: baseline until 2027-02-19") {
		t.Fatalf("scan with the baseline exit %d: %s", code, stdout)
	}

	before, err := os.ReadFile("b.json")
	if err != nil {
		t.Fatal(err)
	}
	broken := vulnerableSQL()
	broken.fail = map[string]error{"ssrf": errors.New("connection reset")}
	code, _, stderr = runScanWith(baselineDeps(broken, baselineToday), "scan", "--config", cfg, "--record", "--baseline", "b.json", "--baseline-write")
	after, _ := os.ReadFile("b.json")
	if code != exitcode.Incomplete || !strings.Contains(stderr, "nothing written: the run is incomplete") || !bytes.Equal(before, after) {
		t.Fatalf("incomplete write exit %d, file changed %v: %s", code, !bytes.Equal(before, after), stderr)
	}
}

// A baseline never makes a run complete: suppressing every finding of an
// incomplete run still exits 4, and a not-evaluated finding stays listed
// as one (#27: suppression never applies to not evaluated).
func TestBaselineNeverHidesIncomplete(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	deps := baselineDeps(vulnerableSQL(), baselineToday)
	if code, _, stderr := runScanWith(deps, "scan", "--config", cfg, "--baseline", "b.json", "--baseline-write"); code != exitcode.GateExceeded {
		t.Fatalf("write exit %d: %s", code, stderr)
	}
	broken := vulnerableSQL()
	broken.fail = map[string]error{"ssrf": errors.New("connection reset")}
	code, stdout, _ := runScanWith(baselineDeps(broken, baselineToday), "scan", "--config", cfg, "--record", "--baseline", "b.json")
	if code != exitcode.Incomplete || !strings.Contains(stdout, "INCOMPLETE RUN") {
		t.Fatalf("exit %d, want 4:\n%s", code, stdout)
	}
	for _, f := range lastReport(t).Findings {
		if f.Suppressed() && f.Status != report.StatusProbable && f.Status != report.StatusVerified {
			t.Errorf("finding %s (%s) suppressed", f.ID, f.Status)
		}
	}
}

// Protection (#27): a baseline file the scan cannot trust exits 2 before
// any model call: malformed, wildcards, traversal, a far-future expiry, an
// accepted risk without a reason, oversized, missing, or a link.
func TestScanRefusesHostileBaseline(t *testing.T) {
	entry := func(fields string) string {
		e := map[string]any{"kind": "accepted", "fingerprint": "0123456789abcdef0123456789abcdef", "class": "sqli", "path": "app.py", "expires": "2027-01-01", "reason": "r"}
		if err := json.Unmarshal([]byte("{"+strings.TrimPrefix(fields, ",")+"}"), &e); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(map[string]any{"version": 1, "entries": []any{e}})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	tests := []struct {
		name    string
		content string // "" means no file
		want    string
	}{
		{"malformed", "{not json", "not the baseline JSON format"},
		{"wildcard fingerprint", entry(`, "fingerprint": "*"`), "fingerprint"},
		{"wildcard class", entry(`, "class": "*"`), "class"},
		{"traversal", entry(`, "path": "../../etc/passwd"`), "path"},
		{"far future", entry(`, "expires": "2099-01-01"`), "more than 365 days"},
		{"no reason", entry(`, "reason": ""`), "reason"},
		{"unknown key", entry(`, "all": true`), "not the baseline JSON format"},
		{"key in another case", entry(`, "Expires": "2099-01-01"`), "unknown as spelled, or repeated"},
		{"huge", `{"version": 1, "entries": [], "pad": "` + strings.Repeat("x", 1<<20) + `"}`, "larger than"},
		{"missing", "", "does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			if tt.content != "" {
				mustWrite(t, "b.json", tt.content)
			}
			m := vulnerableSQL()
			code, _, stderr := runScanWith(baselineDeps(m, baselineToday), "scan", "--config", cfg, "--baseline", "b.json")
			if code != exitcode.ConfigError || !strings.Contains(stderr, tt.want) || m.calls != 0 {
				t.Errorf("exit %d after %d model calls, want 2 naming %q: %s", code, m.calls, tt.want, stderr)
			}
		})
	}
}

// The repository can plant a link where the baseline is: scan never reads
// through it, and accept and --baseline-write never write through it.
func TestBaselineLinkRefused(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	target := filepath.Join(t.TempDir(), "outside.json")
	mustWrite(t, target, `{"version": 1, "entries": []}`)
	if err := os.Symlink(target, "b.json"); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	deps := baselineDeps(vulnerableSQL(), baselineToday)
	for _, args := range [][]string{
		{"scan", "--config", cfg, "--baseline", "b.json"},
		{"scan", "--config", cfg, "--baseline", "b.json", "--baseline-write"},
	} {
		if code, _, stderr := runScanWith(deps, args...); code != exitcode.ConfigError || !strings.Contains(stderr, "not a link") {
			t.Errorf("%v: exit %d: %s", args, code, stderr)
		}
	}
	if err := writeBaselineFile("b.json", &baseline.File{Version: baseline.Version}); err == nil {
		t.Error("writeBaselineFile wrote through a link")
	}
	if data, _ := os.ReadFile(target); string(data) != `{"version": 1, "entries": []}` {
		t.Errorf("the link's target changed: %s", data)
	}
}

func TestBaselineFlagRules(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"baseline on why", []string{"why", "sink-1", "--baseline", "b.json"}, "only for scan and accept"},
		{"baseline on estimate", []string{"estimate", "--baseline", "b.json"}, "only for scan and accept"},
		{"empty baseline", []string{"scan", "--baseline="}, "needs a file path"},
		{"write without baseline", []string{"scan", "--baseline-write"}, "needs --baseline"},
		{"write on accept", []string{"accept", "sink-1", "--baseline-write", "--baseline", "b.json"}, "only for scan"},
		{"expires on scan", []string{"scan", "--expires", "90d"}, "only for accept"},
		{"reason on scan", []string{"scan", "--reason", "x"}, "only for accept"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := run(tt.args...)
			if code != exitcode.ConfigError || !strings.Contains(stderr, tt.want) {
				t.Errorf("exit %d: %s", code, stderr)
			}
		})
	}
}
