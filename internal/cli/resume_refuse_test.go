package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/sandbox"
)

const resumeModel = "model:\n  contract: openai\n  endpoint: https://models.example.invalid/v1\n  name: test-model\n"

// killedRun scans files and kills the scan at its first reader call, after
// it recorded its files, its tier and its discovery; it returns the config
// path and the run ID.
func killedRun(t *testing.T, files map[string]string, extra string, deps func(*cutModel) scanDeps, flags ...string) (cfg, id string) {
	t.Helper()
	cfg = scanRepo(t, files, extra)
	m := newCutModel(sqliVulnerable, "reader", 1)
	if !runKilled(deps(m), append([]string{"scan", "--config", cfg}, flags...)...) {
		t.Fatal("the scan was not cut")
	}
	return cfg, onlyRun(t)
}

func tierMDeps(m *cutModel) scanDeps { return cutDeps(m, calibrate.TierM) }

// rewrite replaces a file the test made: its config, its repository or its
// own run state, all under t.TempDir().
func rewrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil { //nolint:gosec // G703: a path the test made under t.TempDir()
		t.Fatal(err)
	}
}

// Acceptance (#335): a resume whose settings, files or calibration differ
// from the run's is refused with exit 2 before anything is sent, names
// what differs and points to a new creep scan; the run stays resumable.
func TestResumeRefusesChangedRun(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, cfg string, deps *scanDeps)
		flags  []string
		want   string
	}{
		{"config", func(t *testing.T, cfg string, _ *scanDeps) {
			rewrite(t, cfg, resumeModel+"budget:\n  max_calls: 77\n")
		}, nil, "resolved config"},
		{"model name", func(t *testing.T, cfg string, _ *scanDeps) {
			rewrite(t, cfg, strings.Replace(resumeModel, "test-model", "other-model", 1))
		}, nil, "model name"},
		{"endpoint", func(t *testing.T, cfg string, _ *scanDeps) {
			rewrite(t, cfg, strings.Replace(resumeModel, "models.example", "other.example", 1))
		}, nil, "model endpoint"},
		{"mode", nil, []string{"--mode", "nightly"}, "scan mode"},
		{"stability", nil, []string{"--stability", "2"}, "scan flags"},
		{"state mode", nil, []string{"--replay"}, "state mode"},
		{"file content", func(t *testing.T, _ string, _ *scanDeps) {
			data, _ := os.ReadFile("app.py")
			rewrite(t, "app.py", string(data)+"\n# changed\n")
		}, nil, "file list or a file's content"},
		{"file added", func(t *testing.T, _ string, _ *scanDeps) {
			rewrite(t, "extra.py", "print(1)\n")
		}, nil, "file list or a file's content"},
		{"tier", func(_ *testing.T, _ string, deps *scanDeps) {
			deps.calibrate = fixedCalibration(calibrate.TierS, nil)
		}, nil, "calibrated tier"},
		{"calibration expired", func(_ *testing.T, _ string, deps *scanDeps) {
			deps.calibrate = func(_ context.Context, opts calibrate.CacheOptions) (calibrate.Calibration, error) {
				if !opts.CacheOnly {
					return calibrate.Calibration{}, errorString("resume measured the model again")
				}
				return calibrate.Calibration{}, calibrate.ErrNotCached
			}
		}, nil, "calibration (it is no longer cached)"},
	}
	files := resumeFiles(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, id := killedRun(t, files, "", tierMDeps)
			m := newCutModel(sqliVulnerable, "", 0)
			deps := tierMDeps(m)
			if tt.change != nil {
				tt.change(t, cfg, &deps)
			}
			code, out, errOut := runScanWith(deps, append([]string{"resume", id, "--config", cfg}, tt.flags...)...)
			if code != exitcode.ConfigError || out != "" || len(m.bodies) != 0 {
				t.Fatalf("exit %d after %d calls, stdout %q; want exit 2, nothing sent\n%s", code, len(m.bodies), out, errOut)
			}
			if !strings.Contains(errOut, tt.want) || !strings.Contains(errOut, "start a new run with creep scan") {
				t.Fatalf("stderr %q; want %q and a pointer to creep scan", errOut, tt.want)
			}
			if _, err := loadResumable(id); err != nil {
				t.Fatalf("a refused resume changed the run: %v", err)
			}
		})
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

// Protection (#335, threat model R18): a run whose state was edited, cut
// short or signed by another user's secret is refused before anything is
// sent; the state MAC covers every line, the header included.
func TestResumeRefusesDamagedRun(t *testing.T) {
	tests := []struct {
		name   string
		damage func(t *testing.T, events string)
	}{
		{"tampered step", func(t *testing.T, events string) {
			data, _ := os.ReadFile(events)
			rewrite(t, events, string(bytes.Replace(data, []byte(`"tier:M"`), []byte(`"tier:L"`), 1)))
		}},
		{"truncated", func(t *testing.T, events string) {
			data, _ := os.ReadFile(events)
			rewrite(t, events, string(data[:len(data)-10]))
		}},
		{"foreign", func(t *testing.T, _ string) { isolateUserConfig(t) }},
	}
	files := resumeFiles(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, id := killedRun(t, files, "", tierMDeps)
			tt.damage(t, filepath.Join(stateDir, "runs", id, "events.jsonl"))
			m := newCutModel(sqliVulnerable, "", 0)
			code, _, errOut := runScanWith(tierMDeps(m), "resume", id, "--config", cfg)
			if code != exitcode.ConfigError || len(m.bodies) != 0 || !strings.Contains(errOut, "state file corrupt") {
				t.Fatalf("exit %d after %d calls: %s; want exit 2, corrupt, nothing sent", code, len(m.bodies), errOut)
			}
		})
	}
}

// Acceptance (#335): budget.max_seconds counts the time the original run
// spent. A run that already used its deadline is cut during the resume's
// files digest (v0.4 release pentest P1; tester T3): exit 4, nothing sent,
// a time: step recorded and the run still resumable.
func TestResumeKeepsSpentDeadline(t *testing.T) {
	budget := "budget:\n  max_seconds: 60\n"
	clocked := func(m *cutModel) scanDeps {
		deps := tierMDeps(m)
		deps.sandbox.now = steppedClock(61 * time.Second)
		return deps
	}
	cfg, id := killedRun(t, resumeFiles(t), budget, clocked)
	m := newCutModel(sqliVulnerable, "", 0)
	code, _, errOut := runScanWith(tierMDeps(m), "resume", id, "--config", cfg)
	if code != exitcode.Incomplete || len(m.bodies) != 0 || !strings.Contains(errOut, "scan deadline") {
		t.Fatalf("exit %d after %d calls: %s; want the deadline to cut the resumed run", code, len(m.bodies), errOut)
	}
	if !strings.Contains(errOut, "while creep hashed the repository's files") {
		t.Fatalf("stderr %s; want the files digest named as cut", errOut)
	}
	if events := readState(t, filepath.Join("runs", id, "events.jsonl")); !strings.Contains(events, `"step":"time:`) {
		t.Fatalf("the cut digest recorded no time: step:\n%s", events)
	}
	if _, err := loadResumable(id); err != nil {
		t.Fatalf("the cut run was ended or damaged: %v", err)
	}
}

// Acceptance (#335): a nightly resume never reuses what the interrupted
// run built: its sandbox has a name of its own and the app is built again.
func TestNightlyResumeRebuilds(t *testing.T) {
	var ids []string
	fb := &fakeBuilder{app: sandbox.App{Unavailable: sandbox.BuildNoFile}}
	nightly := func(m *cutModel) scanDeps {
		opened := 0
		deps := withBuilder(tierMDeps(m), fb, nil, &opened)
		open := deps.sandbox.open
		deps.sandbox.open = func(st sandbox.Status, runID string, mirror sandbox.Mirror) (appSandbox, error) {
			ids = append(ids, runID)
			return open(st, runID, mirror)
		}
		return deps
	}
	cfg, id := killedRun(t, resumeFiles(t), sandboxOn, nightly, "--mode", "nightly")
	code, _, errOut := runScanWith(nightly(newCutModel(sqliVulnerable, "", 0)), "resume", id, "--config", cfg, "--mode", "nightly")
	if code != exitcode.GateExceeded {
		t.Fatalf("resume exit %d: %s", code, errOut)
	}
	if len(ids) != 1 || ids[0] == id || !strings.HasPrefix(ids[0], id+"-resume-") || fb.builds != 1 {
		t.Fatalf("sandboxes %v, %d builds; want one new sandbox for run %s, built again", ids, fb.builds, id)
	}
}
