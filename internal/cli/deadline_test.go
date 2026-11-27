package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/state"
)

// deadlineOverrun bounds how long a run may go on past a 1 s deadline: it
// covers one detector's pass under -race. A run the
// crafted file kept alive would take minutes (redact.MaxFileBytes).
const deadlineOverrun = 45 * time.Second

// Protection (#260): neither a file crafted to make redaction take minutes
// nor a model call that never returns keeps a run alive past
// budget.max_seconds. The run writes its report, lists what it did not
// reach, exits 4 with reason budget and is never clean. The project file
// may lower the deadline (and the run still ends incomplete) but never
// raise it.
func TestScanDeadlineEndsRunIncomplete(t *testing.T) {
	tests := []struct {
		name      string
		app       string // app.py content
		project   string // ./creep.yaml, "" for none
		user      string // user config, "" for none
		hang      bool   // the model never answers
		wantCode  int
		wantFiles []string // app.py's accepted reasons in not_evaluated; nil: not checked
		wantSinks []string // accepted finding reasons
	}{
		// The deadline cuts discovery's redaction (redact_failed), so the
		// tripwire never sees the file and no sink is planned.
		{"file crafted to redact slowly", craftedSlowApp(t), "", "budget:\n  max_seconds: 1\n", false, exitcode.Incomplete,
			[]string{"redact_failed", "budget"}, []string{"file_not_scanned", "budget"}},
		{"model call outlives the deadline", "@flask", "", "budget:\n  max_seconds: 1\n", true, exitcode.Incomplete, nil, []string{"budget"}},
		{"project file lowers the deadline", "@flask", "budget:\n  max_seconds: 1\n", "", true, exitcode.Incomplete, nil, []string{"budget"}},
		{"within the deadline", "@flask", "", "", false, exitcode.GateExceeded, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"app.py": tt.app}
			if tt.project != "" {
				files["creep.yaml"] = tt.project
			}
			scanRepo(t, files, "")
			setOperatorPolicy(t)
			if tt.user != "" {
				writeUserConfig(t, tt.user)
			}
			m := &fakeModel{verdict: map[string]string{"sql_injection": "vulnerable"}}
			start := time.Now()
			code, out, errOut := runScanWith(deadlineDeps(m, tt.hang), "scan")
			if took := time.Since(start); took > time.Second+deadlineOverrun {
				t.Fatalf("run took %v past a 1 s deadline", took)
			}
			if code != tt.wantCode {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out, errOut)
			}
			rep := readScanReport(t)
			if tt.wantCode != exitcode.Incomplete {
				return
			}
			checkDeadlineReport(t, rep, errOut, tt.wantFiles, tt.wantSinks)
		})
	}
}

// Past the deadline discovery reads no file and calls no model, lists every
// file it would open as budget, and still returns a result, so the run
// reaches its report; a file named as a text format is not_code, as in any
// run.
func TestDiscoveryPastDeadlineListsFilesLeft(t *testing.T) {
	scanRepo(t, map[string]string{"a.py": "@flask", "web/b.js": "@express", "c.go": "package c\n", "README.md": "# r\n"}, "")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errScanDeadline)
	m := &fakeModel{}
	rs := discoverWithin(t, ctx, m, calibrate.TierM)
	want := []report.NotEvaluated{
		{Path: "README.md", Reason: report.SkipNotCode},
		{Path: "a.py", Reason: report.SkipBudget},
		{Path: "c.go", Reason: report.SkipBudget},
		{Path: "web/b.js", Reason: report.SkipBudget},
	}
	if !slices.Equal(rs.gaps, want) || len(rs.res.Sinks) != 0 || m.calls != 0 {
		t.Fatalf("gaps = %+v, %d sinks, %d calls; want %+v, none and none", rs.gaps, len(rs.res.Sinks), m.calls, want)
	}
}

// A recorded answer needs no transport, so --replay and --record check the
// deadline themselves: past it no answer is served and nothing is sent.
func TestRecordedSendStopsPastDeadline(t *testing.T) {
	store, err := state.OpenWithSecret(filepath.Join(t.TempDir(), "state"), make([]byte, state.SecretBytes))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sent := 0
	send := func(context.Context, gateway.Call) (*gateway.Reply, error) {
		sent++
		return &gateway.Reply{ID: "live", Status: 200, Body: []byte("{}")}, nil
	}
	call := gateway.Call{Endpoint: "https://models.example.invalid/v1", Model: "m", Purpose: "reader", Payload: []byte("p")}
	if _, err := recordedSend(store, state.ModeRecord, send)(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	done, cancel := context.WithCancelCause(context.Background())
	cancel(errScanDeadline)
	for _, mode := range []state.Mode{state.ModeRecord, state.ModeReplay, state.ModeLive} {
		reply, err := recordedSend(store, mode, send)(done, call)
		if !errors.Is(err, errScanDeadline) || reply != nil {
			t.Errorf("mode %v past the deadline: reply %v, err %v", mode, reply, err)
		}
	}
	if sent != 1 {
		t.Errorf("sent %d calls, want only the one recorded before the deadline", sent)
	}
}

func TestProjectFileCannotRaiseDeadline(t *testing.T) {
	scanRepo(t, map[string]string{"app.py": "@flask", "creep.yaml": "budget:\n  max_seconds: 7201\n"}, "")
	setOperatorPolicy(t)
	code, out, errOut := runScanWith(deadlineDeps(&fakeModel{}, true), "scan")
	checkScanResult(t, code, out, errOut, exitcode.ConfigError, `key "budget.max_seconds" cannot raise 7200 to 7201 in the project file`)
}

func checkDeadlineReport(t *testing.T, rep *report.Report, errOut string, wantFiles, wantSinks []string) {
	t.Helper()
	if !rep.Run.Incomplete || rep.Run.Reason != reasonDeadline {
		t.Errorf("run = %+v, want incomplete with reason %s", rep.Run, reasonDeadline)
	}
	if !strings.Contains(errOut, "scan deadline of 1 s (budget.max_seconds) passed") {
		t.Errorf("stderr does not name the deadline:\n%s", errOut)
	}
	for _, f := range rep.Findings {
		if f.Status != report.StatusNotEvaluated || !slices.Contains(wantSinks, f.Reason) {
			t.Errorf("finding %s = %s (%s), want not evaluated with one of %v", f.ID, f.Status, f.Reason, wantSinks)
		}
	}
	if wantFiles == nil {
		return
	}
	for _, n := range rep.Coverage.NotEvaluated {
		if n.Path == "app.py" && slices.Contains(wantFiles, string(n.Reason)) {
			return
		}
	}
	t.Errorf("app.py not listed with one of %v: %+v", wantFiles, rep.Coverage.NotEvaluated)
}

// deadlineDeps is fakeDeps with the run's user config applied; with hang
// the model blocks until the run's context is done, as a stalled call
// does before the gateway's own timers fire.
func deadlineDeps(m *fakeModel, hang bool) scanDeps {
	deps := fakeDeps(m, calibrate.TierM)
	deps.connect = func(*config.Resolved, string, io.Writer) (modelLink, error) {
		send := func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
			if !hang {
				return m.send(ctx, c)
			}
			<-ctx.Done()
			return nil, fmt.Errorf("send: %w", ctx.Err())
		}
		return modelLink{send: send, close: func() error { return nil }}, nil
	}
	return deps
}

func readScanReport(t *testing.T) *report.Report {
	t.Helper()
	f, err := os.Open(filepath.Join(stateDir, "report.json"))
	if err != nil {
		t.Fatalf("no report: %v", err)
	}
	defer f.Close()
	rep, err := report.ReadJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

var (
	keywordList = regexp.MustCompile(`(?s)keywords = \[(.*?)\]`)
	quoted      = regexp.MustCompile(`"([^"]*)"`)
)

// craftedSlowApp is the vulnerable Flask app padded to redact's file cap
// with lines that hold every redaction rule's keywords, then short word
// lines: every rule wakes and scans the whole file, so redacting it takes
// minutes (redact.MaxFileBytes, BenchmarkFileEveryKeyword).
func craftedSlowApp(t *testing.T) string {
	t.Helper()
	rules, err := os.ReadFile(filepath.Join("..", "redact", "rules", "gitleaks.toml"))
	if err != nil {
		t.Fatal(err)
	}
	end := "\"\"\"\n"
	var b strings.Builder
	b.WriteString(testApp(t, "flask") + "\nNOTES = r\"\"\"\n")
	for _, list := range keywordList.FindAllStringSubmatch(string(rules), -1) {
		for _, kw := range quoted.FindAllStringSubmatch(list[1], -1) {
			b.WriteString(kw[1] + " ")
		}
		b.WriteString("\n")
	}
	line := strings.Repeat("a", 99) + "\n"
	for b.Len()+len(line)+len(end) <= redact.MaxFileBytes {
		b.WriteString(line)
	}
	return b.String() + end
}
