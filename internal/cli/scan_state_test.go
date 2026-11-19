package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/state"
)

// Acceptance (#160): a .creep the repository planted, or one another creep
// holds, stops the scan before anything is scanned or reported: exit 2 with
// the reason, no report, and the other run's log still loads.
func TestScanRefusesPlantedOrHeldState(t *testing.T) {
	tests := []struct {
		name  string
		plant func(t *testing.T)
		want  string
	}{
		{"state dir is a file", func(t *testing.T) { writeRepoFile(t, stateDir, "") }, "not a directory: unsafe state path"},
		{"state dir is a link", func(t *testing.T) {
			if err := os.Symlink(t.TempDir(), stateDir); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
		}, "unsafe state path"},
		{"lock is a directory", func(t *testing.T) { mkdirRepo(t, filepath.Join(stateDir, "lock")) }, "unsafe state path"},
		{"another creep holds the state", func(t *testing.T) { holdState(t) }, "in use by another creep process"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			tt.plant(t)
			m := &fakeModel{}
			code, stdout, stderr := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--config", cfg)
			if code != exitcode.ConfigError || stdout != "" || !strings.Contains(stderr, tt.want) || m.calls != 0 {
				t.Fatalf("exit %d after %d calls, stdout %q, stderr %q; want 2 naming %q", code, m.calls, stdout, stderr, tt.want)
			}
			if _, err := os.Lstat(filepath.Join(stateDir, "report.json")); err == nil {
				t.Fatal("a refused scan left a report")
			}
		})
	}
}

// creep resume fails the same way while a scan holds the run state.
func TestResumeRefusesHeldState(t *testing.T) {
	scanRepo(t, nil, "")
	id := holdState(t)
	code, _, stderr := run("resume", id)
	if code != exitcode.ConfigError || !strings.Contains(stderr, "in use by another creep process") {
		t.Fatalf("resume of a held run = %d, %q; want 2, in use", code, stderr)
	}
}

// holdState opens a run on the repository's .creep as another creep would
// and keeps it open for the test. After the test it checks the holder's log
// still loads with its step.
func holdState(t *testing.T) string {
	t.Helper()
	s, err := state.OpenUser(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.NewRun(state.ModeLive)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.StepDone("holder"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		sum, err := s.Load(r.ID())
		if err != nil || len(sum.Steps) != 1 {
			t.Errorf("holder's log after the refused scan = %+v, %v", sum, err)
		}
		_ = s.Close()
	})
	return r.ID()
}

// Acceptance (#160): malformed cache entries planted in the repository
// never stand in for the model. Replay fails closed: the run is incomplete
// (exit 4), never clean. Live treats each as a miss, so the scan reaches
// the real verdicts (here a gate-exceeding finding) and records them over
// every regular file; a directory or link is left alone and stays
// unrecorded, even a link to an entry this user signed.
func TestScanPlantedCacheEntries(t *testing.T) {
	tests := []struct {
		name       string
		plant      func(t *testing.T, entry string, data []byte)
		overwrites bool
	}{
		{"no newline", func(t *testing.T, e string, d []byte) { writeRepoFile(t, e, string(bytes.TrimSuffix(d, []byte("\n")))) }, true},
		{"two lines", func(t *testing.T, e string, d []byte) { writeRepoFile(t, e, string(d)+string(d)) }, true},
		{"unsigned clean answer", func(t *testing.T, e string, _ []byte) { writeRepoFile(t, e, `{"v":1,"response":"e30="}`+"\n") }, true},
		{"oversized", func(t *testing.T, e string, _ []byte) {
			writeRepoFile(t, e, strings.Repeat(" ", 2*state.MaxResponseBytes))
		}, true},
		{"directory", func(t *testing.T, e string, _ []byte) {
			if err := os.Remove(e); err != nil {
				t.Fatal(err)
			}
			mkdirRepo(t, filepath.Join(e, "inner"))
		}, false},
		{"link to a signed entry", func(t *testing.T, e string, d []byte) {
			outside := filepath.Join(t.TempDir(), "entry.json")
			writeRepoFile(t, outside, string(d))
			if err := os.Remove(e); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, e); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			real := map[string]string{"sql_injection": "vulnerable"}
			code, recorded, errOut := runScanWith(fakeDeps(&fakeModel{verdict: real}, calibrate.TierM), "scan", "--record", "--config", cfg)
			if code != exitcode.GateExceeded {
				t.Fatalf("record: exit %d\n%s", code, errOut)
			}
			entries := plantCache(t, tt.plant)
			code, out, _ := runScanWith(fakeDeps(offlineModel(), calibrate.TierM), "scan", "--replay", "--config", cfg)
			if code != exitcode.Incomplete || !strings.Contains(out, "INCOMPLETE RUN") {
				t.Fatalf("replay of planted entries: exit %d; want 4, incomplete\n%s", code, out)
			}
			live := &fakeModel{verdict: real}
			code, out, errOut = runScanWith(fakeDeps(live, calibrate.TierM), "scan", "--config", cfg)
			if code != exitcode.GateExceeded || out != recorded || live.calls != entries-1 { // one entry is the discovery seed, not a model call
				t.Fatalf("live: exit %d after %d calls for %d entries; want 1, the model's verdicts\n%s\n%s", code, live.calls, entries, out, errOut)
			}
			want := exitcode.Incomplete
			if tt.overwrites {
				want = exitcode.GateExceeded
			}
			if code, _, _ := runScanWith(fakeDeps(offlineModel(), calibrate.TierM), "scan", "--replay", "--config", cfg); code != want {
				t.Fatalf("replay after live: exit %d; want %d", code, want)
			}
		})
	}
}

// plantCache applies plant to every recorded cache entry and returns how
// many there are.
func plantCache(t *testing.T, plant func(t *testing.T, entry string, data []byte)) int {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(stateDir, "cache", "*.json"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no recorded cache entries: %v", err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(e)
		if err != nil {
			t.Fatal(err)
		}
		plant(t, e, data)
	}
	return len(entries)
}

// offlineModel fails every discovery and reader call, so a replay that reached it would
// show as a send failure and a call count.
func offlineModel() *fakeModel {
	m := &fakeModel{fail: map[string]error{}}
	for _, class := range []string{"discover", "sql_injection", "ssrf", "path_traversal", "command_injection", "template_injection", "nosql_injection"} {
		m.fail[class] = errors.New("replay must not call the model")
	}
	return m
}

func writeRepoFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil { //nolint:gosec // G703: the test plants files in its own temporary repository
		t.Fatal(err)
	}
}

func mkdirRepo(t *testing.T, name string) {
	t.Helper()
	if err := os.MkdirAll(name, 0o700); err != nil {
		t.Fatal(err)
	}
}
