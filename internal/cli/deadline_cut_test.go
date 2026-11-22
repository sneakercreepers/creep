package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/gitindex/gitindextest"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/report"
)

// Protection (#260): past the deadline the slicer reads nothing from disk,
// and every file it did not slice is still listed. The deadline is a cancel
// at a fixed point, never a wall-clock race: before slicing, every discovered
// file and its sinks are budget; during the first file's redaction, that
// file is redact_failed (its sinks file_not_scanned) and the files after it
// are budget, unread. No model call is made either way (the stage has no
// model, so a call would panic).
func TestDeadlineListsUnreachedFilesAsBudget(t *testing.T) {
	tests := []struct {
		name     string
		cancelAt string // cancel when this file is read; "" cancels before slicing
		wantCut  string // the file listed redact_failed, or ""
	}{
		{"deadline before slicing", "", ""},
		{"deadline during the first file's redaction", "a.py", "a.py"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := walkFlaskFiles(t, "a.py", "b.py", "c.py")
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			if tt.cancelAt == "" {
				cancel(errScanDeadline)
			}
			gaps, findings := readPastDeadline(t, ctx, rs, func(path string) ([]byte, error) {
				if path == tt.cancelAt {
					cancel(errScanDeadline)
				}
				return os.ReadFile(path)
			})
			checkUnreachedFiles(t, gaps, findings, tt.wantCut)
		})
	}
}

// walkFlaskFiles writes the vulnerable Flask app under each name and walks
// the repository and runs discovery on it with no deadline.
func walkFlaskFiles(t *testing.T, names ...string) repoScan {
	t.Helper()
	files := map[string]string{}
	for _, n := range names {
		files[n] = "@flask"
	}
	scanRepo(t, files, "")
	rs := discoverHere(t, &fakeModel{}, calibrate.TierM)
	if len(rs.gaps) != 0 || len(rs.res.Sinks) == 0 {
		t.Fatalf("discovery: gaps %+v, %d sinks", rs.gaps, len(rs.res.Sinks))
	}
	return rs
}

// readPastDeadline plans rs at tier M and runs the read stage under ctx,
// with the scan's deadline-aware Read around read.
func readPastDeadline(t *testing.T, ctx context.Context, rs repoScan, read func(string) ([]byte, error)) ([]report.NotEvaluated, []report.Finding) {
	t.Helper()
	findings := baseFindings(rs)
	ptier, err := plannerTier(calibrate.TierM)
	if err != nil {
		t.Fatal(err)
	}
	rtier, err := readerTier(calibrate.TierM)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planSinks(rs, ptier, planBudget(2_000_000, rtier, 1), findings, nil)
	if err != nil {
		t.Fatal(err)
	}
	red, err := redact.NewWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reads := newDeadlineReads(ctx, read)
	stage := readStage{tier: rtier, reads: reads, slicer: reader.Slicer{Redactor: red, Tier: rtier, Read: reads.Read}}
	gaps, _, err := stage.run(ctx, plan, rs, findings)
	if err != nil {
		t.Fatal(err)
	}
	return gaps, findings
}

// checkUnreachedFiles requires each file listed once: cut as redact_failed
// with its sinks file_not_scanned, every other file and sink as budget.
func checkUnreachedFiles(t *testing.T, gaps []report.NotEvaluated, findings []report.Finding, cut string) {
	t.Helper()
	var want []report.NotEvaluated
	for _, p := range []string{"a.py", "b.py", "c.py"} {
		reason := report.SkipBudget
		if p == cut {
			reason = report.SkipReason(gateway.SkipRedactFailed)
		}
		want = append(want, report.NotEvaluated{Path: p, Reason: reason})
	}
	if !slices.Equal(gaps, want) {
		t.Errorf("files = %+v, want %+v", gaps, want)
	}
	for _, f := range findings {
		reason := reasonDeadline
		if f.Path == cut {
			reason = string(reader.SkipFileNotScanned)
		}
		if f.Status != report.StatusNotEvaluated || f.Reason != reason {
			t.Errorf("finding %s in %s = %s (%s), want not evaluated (%s)", f.ID, f.Path, f.Status, f.Reason, reason)
		}
	}
}

// Past the deadline the vendor-tree proof neither reads the git index nor
// stats the tree, so the walk cannot be held there; nothing is proven, so
// a file under an installed tree is listed like first-party code. Before
// the deadline the same tree is proven, so the check is what changed.
func TestVendorProofsStopAtDeadline(t *testing.T) {
	tests := []struct {
		name string
		cut  bool
		want bool
	}{
		{"before the deadline", false, true},
		{"past the deadline", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := t.TempDir()
			writeTreeFile(t, repo, "node_modules/ok/package.json", "{}")
			writeTreeFile(t, repo, gitIndexPath, string(gitindextest.Build(gitindextest.Spec{Version: 2, Paths: []string{"app.py"}})))
			root, err := os.OpenRoot(repo)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			if tt.cut {
				cancel(errScanDeadline)
			}
			proofs := newVendorProofs(ctx, root)
			if got := proofs.proven("node_modules/ok/addon.c"); got != tt.want || proofs.loaded == tt.cut {
				t.Fatalf("proven = %v (index read %v), want %v (index read %v)", got, proofs.loaded, tt.want, !tt.cut)
			}
		})
	}
}

// A discovery the deadline cut says nothing about the repository's routes: the
// report names the deadline, never "no routes found".
func TestDeadlineCutDiscoveryIsNotNoRoutes(t *testing.T) {
	scanRepo(t, map[string]string{"a.py": craftedSlowApp(t), "b.py": "@flask"}, "")
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
			t.Errorf("%s says no routes after a cut discovery:\n%s", name, text)
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
				app = craftedSlowApp(t)
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
