package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/report"
)

// Protection (#260): past the deadline the slicer reads nothing from disk.
// Of three files crafted to redact slowly, at most the one being redacted
// when the deadline passed is redact_failed (its sinks file_not_scanned);
// every file the slicer never reached is listed budget, and so are its
// sinks.
func TestDeadlineListsUnreachedFilesAsBudget(t *testing.T) {
	slow := craftedSlowApp(t, false)
	scanRepo(t, map[string]string{"a.py": slow, "b.py": slow, "c.py": slow}, "")
	setOperatorPolicy(t)
	writeUserConfig(t, "budget:\n  max_seconds: 1\n")
	m := &fakeModel{}
	start := time.Now()
	code, out, errOut := runScanWith(deadlineDeps(m, false), "scan")
	if took := time.Since(start); took > time.Second+deadlineOverrun {
		t.Fatalf("run took %v past a 1 s deadline", took)
	}
	if code != exitcode.Incomplete || m.calls != 0 {
		t.Fatalf("exit %d with %d model calls, want 4 and none\nstdout:\n%s\nstderr:\n%s", code, m.calls, out, errOut)
	}
	rep := readScanReport(t)
	cutFile := checkUnreachedFiles(t, rep.Coverage.NotEvaluated)
	for _, f := range rep.Findings {
		want := reasonDeadline
		if f.Path == cutFile {
			want = string(reader.SkipFileNotScanned)
		}
		if f.Status != report.StatusNotEvaluated || f.Reason != want {
			t.Errorf("finding %s in %s = %s (%s), want not evaluated (%s)", f.ID, f.Path, f.Status, f.Reason, want)
		}
	}
}

// checkUnreachedFiles requires every crafted file listed, at most one as
// redact_failed and the rest as budget, and returns the redact_failed one.
func checkUnreachedFiles(t *testing.T, gaps []report.NotEvaluated) string {
	t.Helper()
	cut, listed := "", map[string]bool{}
	for _, g := range gaps {
		listed[g.Path] = true
		switch {
		case g.Reason == report.SkipBudget:
		case g.Reason == report.SkipReason(gateway.SkipRedactFailed) && cut == "":
			cut = g.Path
		default:
			t.Errorf("%s listed %s, want budget (or one redact_failed)", g.Path, g.Reason)
		}
	}
	for _, p := range []string{"a.py", "b.py", "c.py"} {
		if !listed[p] {
			t.Errorf("%s is not listed: %+v", p, gaps)
		}
	}
	return cut
}

// A walk the deadline cut says nothing about the repository's routes: the
// report names the deadline, never "no routes found".
func TestDeadlineCutWalkIsNotNoRoutes(t *testing.T) {
	scanRepo(t, map[string]string{"a.py": craftedSlowApp(t, true), "b.py": "@flask"}, "")
	setOperatorPolicy(t)
	writeUserConfig(t, "budget:\n  max_seconds: 1\n")
	code, out, errOut := runScanWith(deadlineDeps(&fakeModel{}, false), "scan")
	if code != exitcode.Incomplete {
		t.Fatalf("exit %d, want 4\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	md, err := os.ReadFile(filepath.Join(stateDir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"stdout": out, "report.md": string(md)} {
		if strings.Contains(text, "routes found") || strings.Contains(text, "found no route") {
			t.Errorf("%s says no routes after a cut walk:\n%s", name, text)
		}
	}
	if !strings.Contains(out, "INCOMPLETE RUN (reason budget)") || !strings.Contains(errOut, "scan deadline of 1 s") {
		t.Errorf("the deadline is not named\nstdout:\n%s\nstderr:\n%s", out, errOut)
	}
	if !strings.Contains(string(md), "b.py") {
		t.Errorf("report.md does not list the unreached b.py:\n%s", md)
	}
}

// creep estimate reads and redacts like scan, so the deadline bounds it
// too: a cut estimate says it is partial and exits 4, never 0.
func TestEstimateDeadlineFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		wantCode int
		partial  bool
	}{
		{"cut by the deadline", "budget:\n  max_seconds: 1\n", exitcode.Incomplete, true},
		{"within the deadline", "", exitcode.OK, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := "@flask"
			if tt.partial {
				app = craftedSlowApp(t, false)
			}
			cfg := scanRepo(t, map[string]string{"app.py": app}, tt.config)
			start := time.Now()
			code, out, errOut := runScanWith(offlineDeps(t, true), "estimate", "--config", cfg)
			if took := time.Since(start); took > time.Second+deadlineOverrun {
				t.Fatalf("estimate took %v", took)
			}
			if code != tt.wantCode || strings.Contains(out, "PARTIAL ESTIMATE") != tt.partial {
				t.Fatalf("exit %d, want %d (partial %v)\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, tt.partial, out, errOut)
			}
			if tt.partial && !strings.Contains(out, "reason budget") {
				t.Errorf("the estimate does not name budget:\n%s", out)
			}
		})
	}
}

// deadlineReads touches the disk only before the deadline and relabels
// exactly the files it refused, with their hypotheses.
func TestDeadlineReadsRefuseAfterDeadline(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	reads := 0
	d := newDeadlineReads(ctx, func(string) ([]byte, error) { reads++; return []byte("x\n"), nil })
	if _, err := d.Read("a.py"); err != nil {
		t.Fatal(err)
	}
	cancel(errScanDeadline)
	if _, err := d.Read("b.py"); !errors.Is(err, errScanDeadline) {
		t.Fatalf("read past the deadline: %v", err)
	}
	if reads != 1 {
		t.Fatalf("read the disk %d times, want once (before the deadline)", reads)
	}
	rep := reader.SliceReport{
		NotScanned:   []gateway.NotScanned{{Path: "a.py", Reason: gateway.SkipRedactFailed}, {Path: "b.py", Reason: gateway.SkipReadFailed}},
		NotEvaluated: []reader.NotEvaluated{{Hypothesis: 1, Reason: reader.SkipFileNotScanned}, {Hypothesis: 2, Reason: reader.SkipFileNotScanned}},
	}
	d.relabel(&rep, []reader.Target{{Hypothesis: 1, Path: "a.py"}, {Hypothesis: 2, Path: "b.py"}})
	if rep.NotScanned[0].Reason != gateway.SkipRedactFailed || rep.NotScanned[1].Reason != gateway.SkipBudget {
		t.Errorf("files = %+v, want a.py kept and b.py budget", rep.NotScanned)
	}
	if rep.NotEvaluated[0].Reason != reader.SkipFileNotScanned || string(rep.NotEvaluated[1].Reason) != reasonDeadline {
		t.Errorf("hypotheses = %+v, want 1 kept and 2 budget", rep.NotEvaluated)
	}
}
