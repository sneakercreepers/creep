package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
)

// cutModel is a fakeModel that dies mid-call: the at-th call of purpose
// never returns (runtime.Goexit ends the scan the way a killed process
// does, with no end line), and every request body sent is counted.
type cutModel struct {
	*fakeModel
	purpose string
	at      int // 1-based among the calls of purpose; 0 never cuts
	seen    int
	bodies  map[string]int
}

func newCutModel(verdict map[string]string, purpose string, at int) *cutModel {
	return &cutModel{fakeModel: &fakeModel{verdict: verdict}, purpose: purpose, at: at, bodies: map[string]int{}}
}

func (m *cutModel) send(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
	m.bodies[c.Purpose+"|"+string(c.Payload)]++
	if c.Purpose == m.purpose {
		if m.seen++; m.seen == m.at {
			runtime.Goexit()
		}
	}
	return m.fakeModel.send(ctx, c)
}

func cutDeps(m *cutModel, tier calibrate.Tier) scanDeps {
	deps := fakeDeps(m.fakeModel, tier)
	deps.connect = func(*config.Resolved, string, io.Writer) (modelLink, error) {
		return modelLink{send: m.send, close: func() error { return nil }}, nil
	}
	if m.purpose == "calibrate" {
		deps.calibrate = func(context.Context, calibrate.CacheOptions) (calibrate.Calibration, error) {
			runtime.Goexit()
			return calibrate.Calibration{}, nil
		}
	}
	return deps
}

// runKilled runs the CLI until it exits or dies mid-call, and reports
// whether it died.
func runKilled(deps scanDeps, args ...string) (killed bool) {
	done, finished := make(chan struct{}), false
	go func() {
		defer close(done)
		runScanWith(deps, args...)
		finished = true
	}()
	<-done
	return !finished
}

// onlyRun returns the ID of the one run in .creep.
func onlyRun(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(stateDir, "runs"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("runs: %v, %d entries; want 1", err, len(entries))
	}
	return entries[0].Name()
}

// resumeFiles is the repository every resume test scans, read before any
// test changes directory.
func resumeFiles(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{"app.py": testApp(t, "flask")}
}

// Acceptance (#335): a run killed at any stage resumes to the reports,
// stdout and exit code of a run that was never interrupted, with the same
// responses. No finished step is sent again: only the call the kill cut
// is sent twice, and in record mode too, where every call is otherwise
// sent.
func TestResumeMatchesUninterruptedRun(t *testing.T) {
	tests := []struct {
		name    string
		purpose string // the stage the kill cuts
		at      int
		flags   []string // scan flags
		again   []string // the resume's flags: the record mode comes from the run
		resent  int      // calls sent twice: the one cut mid-flight
	}{
		{"calibrate", "calibrate", 1, nil, nil, 0},
		{"first discovery call", "discover", 1, nil, nil, 1},
		{"first reader call", "reader", 1, nil, nil, 1},
		{"later reader call", "reader", 3, nil, nil, 1},
		{"reader call, record mode", "reader", 2, []string{"--record"}, nil, 1},
		{"second sample, stability", "reader-s2", 1, []string{"--stability", "2"}, []string{"--stability", "2"}, 1},
		{"nightly mode", "reader", 1, []string{"--mode", "nightly"}, []string{"--mode", "nightly"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := resumeFiles(t)
			whole := newCutModel(sqliVulnerable, "", 0)
			cfg := scanRepo(t, files, "")
			wantCode, wantOut, _ := runScanWith(cutDeps(whole, calibrate.TierM), append([]string{"scan", "--config", cfg}, tt.flags...)...)
			wantReports := readReports(t)

			cut := newCutModel(sqliVulnerable, tt.purpose, tt.at)
			cfg = scanRepo(t, files, "")
			if !runKilled(cutDeps(cut, calibrate.TierM), append([]string{"scan", "--config", cfg}, tt.flags...)...) {
				t.Fatal("the scan was not cut")
			}
			rest := newCutModel(sqliVulnerable, "", 0)
			rest.bodies = cut.bodies
			code, out, errOut := runScanWith(cutDeps(rest, calibrate.TierM), append([]string{"resume", onlyRun(t), "--config", cfg}, tt.again...)...)
			if code != wantCode || out != wantOut {
				t.Fatalf("resume: exit %d, want %d\nstdout:\n%s\nwant:\n%s\nstderr: %s", code, wantCode, out, wantOut, errOut)
			}
			for name, want := range wantReports {
				if got := readReports(t)[name]; got != want {
					t.Errorf("%s differs from the uninterrupted run's:\n%s\nwant:\n%s", name, got, want)
				}
			}
			checkSentOnce(t, cut.bodies, len(whole.bodies), tt.resent)
		})
	}
}

// checkSentOnce checks that the killed run and its resume sent each
// request of the uninterrupted run, and only the cut one twice.
func checkSentOnce(t *testing.T, bodies map[string]int, want, resent int) {
	t.Helper()
	twice := 0
	for _, n := range bodies {
		switch {
		case n == 2:
			twice++
		case n != 1:
			t.Fatalf("a request was sent %d times", n)
		}
	}
	if len(bodies) != want || twice != resent {
		t.Fatalf("%d distinct requests, %d sent twice; want %d and %d", len(bodies), twice, want, resent)
	}
}

// A resumed run that completes ends its run: a second resume is refused,
// so the same run cannot be reported twice.
func TestResumedRunEnds(t *testing.T) {
	cfg := scanRepo(t, resumeFiles(t), "")
	if !runKilled(cutDeps(newCutModel(sqliVulnerable, "reader", 1), calibrate.TierM), "scan", "--config", cfg) {
		t.Fatal("the scan was not cut")
	}
	id := onlyRun(t)
	if code, _, errOut := runScanWith(cutDeps(newCutModel(sqliVulnerable, "", 0), calibrate.TierM), "resume", id, "--config", cfg); code != exitcode.GateExceeded {
		t.Fatalf("resume exit %d, want 1: %s", code, errOut)
	}
	m := newCutModel(sqliVulnerable, "", 0)
	code, _, errOut := runScanWith(cutDeps(m, calibrate.TierM), "resume", id, "--config", cfg)
	if code != exitcode.ConfigError || len(m.bodies) != 0 || !bytes.Contains([]byte(errOut), []byte("run already ended")) {
		t.Fatalf("second resume: exit %d after %d calls: %s", code, len(m.bodies), errOut)
	}
}
