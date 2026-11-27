package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/planner"
	"github.com/sneakercreepers/creep/internal/report"
)

// findingKeys lists each finding of the last report as ID, class, path,
// line and status, so two runs can be compared.
func findingKeys(t *testing.T) []string {
	t.Helper()
	rep, err := readLastReport()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range rep.Findings {
		out = append(out, strings.Join([]string{f.ID, f.Class, f.Path, strconv.Itoa(f.Line), string(f.Status)}, " "))
	}
	return out
}

// Protection (ADR 0017 D2, R20): a batch whose answer misses the canary is
// not believed. Its files are parse_failed and the run exits 4 even when
// every candidate is discarded; the tripwire's candidates are still
// evaluated; text and Markdown name the canary, never a syntax error.
func TestMissedCanaryIsIncomplete(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	code, _, _ := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--config", cfg)
	if code != exitcode.OK {
		t.Fatalf("honest model: exit %d, want 0", code)
	}
	honest := findingKeys(t)
	code, out, errOut := runScanWith(fakeDeps(&fakeModel{missCanary: true}, calibrate.TierM), "scan", "--record", "--config", cfg)
	if code != exitcode.Incomplete || !strings.Contains(out, "app.py  parse_failed") || !strings.Contains(out, "INCOMPLETE RUN (reason parse_failed)") {
		t.Fatalf("missed canary: exit %d\n%s\n%s", code, out, errOut)
	}
	if got := findingKeys(t); !slices.Equal(got, honest) || len(got) == 0 {
		t.Fatalf("findings %v, want the honest run's %v", got, honest)
	}
	md, err := os.ReadFile(filepath.Join(stateDir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	note := "discovery canary not found in batch 1"
	if !strings.Contains(out, note) || !strings.Contains(string(md), note) || strings.Contains(out+string(md), "syntax") {
		t.Fatalf("canary note missing or named a syntax error:\n%s\n%s", out, md)
	}
	checkJSONReport(t, string(report.SkipParseFailed))
}

// Protection (#362, R19): a canary cited within the fixed window passes
// the scan; the broken fixture, one line past it, still fails the batch
// and the run exits 4 with parse_failed.
func TestCanaryWindowExitCodes(t *testing.T) {
	tests := []struct {
		shift int
		code  int
	}{
		{0, exitcode.OK},
		{-2, exitcode.OK},
		{-3, exitcode.Incomplete},
	}
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	for _, tt := range tests {
		code, out, errOut := runScanWith(fakeDeps(&fakeModel{canaryShift: tt.shift}, calibrate.TierM), "scan", "--record", "--config", cfg)
		if code != tt.code {
			t.Fatalf("canary sink %d lines off: exit %d, want %d\n%s\n%s", tt.shift, code, tt.code, out, errOut)
		}
		if tt.code == exitcode.Incomplete && !strings.Contains(out, "app.py  parse_failed") {
			t.Fatalf("canary past the window: app.py not parse_failed\n%s", out)
		}
	}
}

// cutOffReply is a chat completion cut off at max_tokens.
var cutOffReply = []byte(`{"id":"fake","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"{\"entries\":[{\"file\":0,"},"finish_reason":"length"}]}`)

// Acceptance (#362): a discovery reply cut off at its cap on every attempt
// (retries counted) lists the batch's files truncated, not parse_failed,
// and the run exits 4; the tripwire's findings stay.
func TestCutOffDiscoveryIsTruncated(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	m := &fakeModel{cutOff: true}
	code, out, errOut := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--record", "--config", cfg)
	if code != exitcode.Incomplete || !strings.Contains(out, "app.py  truncated") || strings.Contains(out, "parse_failed") {
		t.Fatalf("cut-off discovery: exit %d\n%s\n%s", code, out, errOut)
	}
	if m.discovered != 2 {
		t.Errorf("%d discovery calls, want the first and its one retry", m.discovered)
	}
	if len(findingKeys(t)) == 0 {
		t.Error("the tripwire's findings were dropped")
	}
}

// Protection (ADR 0017 D1/D3, R19): model output only adds. A reply that
// claims every line is an auth check removes no candidate and changes no
// verdict, and the planner still gets every sink with the worst-case
// flags: dynamic, not parameterized, not indirect, on a route not
// authenticated that takes every method.
func TestModelOutputNeverLowersCandidates(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask", "web/app.js": "@express"}, "")
	verdict := map[string]string{"sql_injection": "vulnerable", "command_injection": "vulnerable"}
	code, _, _ := runScanWith(fakeDeps(&fakeModel{verdict: verdict}, calibrate.TierM), "scan", "--config", cfg)
	honest := findingKeys(t)
	code2, out, errOut := runScanWith(fakeDeps(&fakeModel{verdict: verdict, claimAuth: true}, calibrate.TierM), "scan", "--record", "--config", cfg)
	if code != exitcode.GateExceeded || code2 != code {
		t.Fatalf("exit %d with auth claimed everywhere, %d without; want %d\n%s\n%s", code2, code, exitcode.GateExceeded, out, errOut)
	}
	if got := findingKeys(t); !slices.Equal(got, honest) || len(got) < 8 {
		t.Fatalf("findings with auth claimed %v, want the honest run's %v", got, honest)
	}
	rs := discoverHere(t, &fakeModel{claimAuth: true}, calibrate.TierM)
	in, _ := plannerInput(rs.res, planner.TierM, planner.Budget{})
	for _, r := range in.Routes {
		if r.Authenticated || r.Methods != plannerMethods(discover.AllMethods) {
			t.Errorf("route %+v lowered", r)
		}
	}
	for _, s := range in.Sinks {
		if !s.DynamicArg || s.Parameterized || s.Indirect {
			t.Errorf("sink %+v lowered", s)
		}
	}
	if len(in.Sinks) != len(honest) {
		t.Errorf("planner got %d sinks, the report %d", len(in.Sinks), len(honest))
	}
}

// ADR 0017 F6 (option A): before any model call the scan says on stderr
// how many whole source files discovery may send and where; Markdown
// counts the files it sent. A replay sends nothing, so it says nothing.
func TestScanNoticeAndWholeFileCount(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask", "lib/util.go": "package lib\n", "README.md": "# x\n"}, "")
	code, out, errOut := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--record", "--config", cfg)
	notice := "creep scan: discovery sends up to 2 whole source files, each redacted, to endpoint https://models.example.invalid/v1"
	if code != exitcode.OK || !strings.HasPrefix(errOut, notice) || strings.Contains(out, notice) {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	md, err := os.ReadFile(filepath.Join(stateDir, "report.md"))
	if err != nil || !strings.Contains(string(md), "Discovery sent 2 whole source files, each redacted") {
		t.Fatalf("Markdown lacks the count (%v):\n%s", err, md)
	}
	_, _, errOut = runScanWith(fakeDeps(offlineModel(), calibrate.TierM), "scan", "--replay", "--config", cfg)
	if strings.Contains(errOut, "discovery sends") {
		t.Fatalf("replay printed the egress notice: %s", errOut)
	}
}

// The notice names where whole files go: the endpoint over HTTP, and for
// a model CLI its program, preset and the consent key egress.log uses.
func TestWholeFileTargetNamesTheModel(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m := config.Model{Contract: "command", Run: `"` + self + `" -p`, TimeoutSeconds: 60, MaxOutputBytes: 1 << 20}
	cmd, err := newModelCommand(m, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	preset := m
	preset.Preset = "claude-code"
	tests := []struct {
		name string
		m    config.Model
		cmd  *gateway.Command
		want string
	}{
		{"http", config.Model{Contract: "openai", Endpoint: "https://models.example.invalid/v1"}, nil, "endpoint https://models.example.invalid/v1"},
		{"command", m, cmd, "the model command " + cmd.Program() + " at " + cmd.Endpoint()},
		{"preset", preset, cmd, "the model command " + cmd.Program() + " (preset claude-code) at " + cmd.Endpoint()},
		{"command not built", m, nil, "the model command (model.run)"},
	}
	for _, tt := range tests {
		if got := wholeFileTarget(tt.m, tt.cmd); got != tt.want {
			t.Errorf("%s: target = %q, want %q", tt.name, got, tt.want)
		}
	}
}
