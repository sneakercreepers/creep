package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
)

// e2eEnv turns on TestOllamaEndToEnd and names the directory its results
// go to: the e2e workflow sets it on a runner with the pinned Ollama model
// and CREEP_POLICY. Elsewhere the test skips, since it calls a live model.
const e2eEnv = "CREEP_OLLAMA_E2E"

// e2eModelEnv labels the results with the model the policy names.
const e2eModelEnv = "CREEP_E2E_MODEL"

var e2eApps = filepath.Join("..", "..", "testdata", "apps")

var (
	statsCalibration = regexp.MustCompile(`(?m)^  calibration: (.*)$`)
	headerTier       = regexp.MustCompile(`· tier ([A-Z]) ·`)
)

// TestOllamaEndToEnd (#367) runs the documented user path on a live local
// model with nothing forced: `creep init`, `doctor`, `estimate`, then
// `creep scan --mode pr --stats` on every test app's vulnerable and safe
// twin, the first scan calibrating for real (fresh cache). A twin refused
// as unfit (exit 3, ADR 0036) is scanned again with --allow-unfit-model,
// so the results still show what the model found. It records exit codes,
// reasons, calibration cost, tier, recall and false positives, and fails
// only when the path itself breaks (exit 2, or no calibration measured):
// a model too small to pass is a result, not a test failure.
func TestOllamaEndToEnd(t *testing.T) {
	out := os.Getenv(e2eEnv)
	if out == "" {
		t.Skipf("%s is not set: this test calls a live local model", e2eEnv)
	}
	isolateUserConfig(t)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	res := e2eResults{Model: os.Getenv(e2eModelEnv), Date: time.Now().UTC().Format(time.DateOnly)}
	twins := e2eTwins(t)
	if len(twins) == 0 {
		t.Fatalf("no app directories under %s", e2eApps)
	}
	res.Init, res.Doctor, res.Estimate = e2ePrelude(t, twins[0])
	writeE2EResults(t, out, res)
	for _, tw := range twins {
		res.Runs = append(res.Runs, e2eScanTwin(t, tw)...)
		// Rewritten after every twin, so a go test timeout still leaves
		// the results so far for the artifact.
		writeE2EResults(t, out, res)
	}
	res.Why = e2eWhy(t, res.Runs)
	writeE2EResults(t, out, res)
	for _, p := range e2ePathProblems(res) {
		t.Error(p)
	}
}

// e2eNotRun is the exit recorded for a step that had nothing to run on.
const e2eNotRun = -1

// e2ePathProblems lists how the user path itself broke: every step but a
// scan must exit 0 (doctor's warnings still exit 0), and no scan may exit
// 2 or skip the calibration it pays for.
func e2ePathProblems(res e2eResults) []string {
	var problems []string
	for _, st := range []e2eStep{res.Init, res.Doctor, res.Estimate, res.Why} {
		if st.Exit != exitcode.OK && st.Exit != e2eNotRun {
			problems = append(problems, fmt.Sprintf("%s: exit %d, want 0: %q", st.Command, st.Exit, st.Lines))
		}
	}
	for _, r := range res.Runs {
		if r.Exit == exitcode.ConfigError {
			problems = append(problems, fmt.Sprintf("%s %s (%s): exit 2: %s", r.App, r.Variant, r.Pass, r.Reason))
		}
	}
	if len(res.Runs) == 0 || res.Runs[0].Calibration == "" {
		problems = append(problems, "the first scan printed no calibration cost")
	}
	return problems
}

// e2eTwin is one variant of one test app and the findings it must have.
type e2eTwin struct {
	app, variant string
	dir          string // absolute: every scan changes the working directory
	expected     []e2eExpected
}

type e2eExpected struct {
	Class string `json:"class"`
	File  string `json:"file"`
	Line  int    `json:"line"`
}

// e2eTwins lists every app's vulnerable then safe twin, in name order.
func e2eTwins(t *testing.T) []e2eTwin {
	t.Helper()
	apps, err := filepath.Abs(e2eApps)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(apps)
	if err != nil {
		t.Fatal(err)
	}
	var twins []e2eTwin
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(apps, e.Name(), "expected.json"))
		if err != nil {
			t.Fatal(err)
		}
		var exp struct{ Vulnerable []e2eExpected }
		if err := json.Unmarshal(data, &exp); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		dir := filepath.Join(apps, e.Name())
		twins = append(twins, e2eTwin{e.Name(), "vulnerable", filepath.Join(dir, "vulnerable"), exp.Vulnerable},
			e2eTwin{e.Name(), "safe", filepath.Join(dir, "safe"), nil})
	}
	return twins
}

// e2ePrelude runs init, doctor and estimate in a copy of the first twin.
func e2ePrelude(t *testing.T, tw e2eTwin) (initStep, doctor, estimate e2eStep) {
	t.Helper()
	e2eRepo(t, tw)
	return e2eRun(nil, "init"), e2eRun(isModelLine, "doctor"), e2eRun(isTierRow, "estimate")
}

// e2eScanTwin scans a fresh copy of tw, and once more past the fitness
// floor when the model was refused as unfit.
func e2eScanTwin(t *testing.T, tw e2eTwin) []e2eScan {
	t.Helper()
	first := e2eScanOnce(t, tw, "default")
	if first.Exit != exitcode.ModelOrSandbox || !strings.Contains(first.Reason, "--allow-unfit-model") {
		return []e2eScan{first}
	}
	return []e2eScan{first, e2eScanOnce(t, tw, "allow-unfit", "--allow-unfit-model")}
}

func e2eScanOnce(t *testing.T, tw e2eTwin, pass string, extra ...string) e2eScan {
	t.Helper()
	repo := e2eRepo(t, tw)
	start := time.Now()
	code, stdout, stderr := e2eExec(append([]string{"scan", "--mode", "pr", "--stats"}, extra...)...)
	s := e2eScan{App: tw.app, Variant: tw.variant, Pass: pass, Exit: code, Seconds: time.Since(start).Round(time.Second).Seconds(), repo: repo, Expected: len(tw.expected)}
	all := stdout + "\n" + stderr
	if m := statsCalibration.FindStringSubmatch(all); m != nil {
		s.Calibration = m[1]
	}
	if m := headerTier.FindStringSubmatch(all); m != nil {
		s.Tier = m[1]
	}
	s.Reason = lastScanLine(stderr)
	if rep := readE2EReport(t, repo); rep != nil {
		s.score(tw.expected, rep)
		if rep.Run.Reason != "" {
			s.Reason = rep.Run.Reason
		}
	}
	t.Logf("%s %s (%s): exit %d in %.0f s\n%s", tw.app, tw.variant, pass, code, s.Seconds, all)
	return s
}

// e2eWhy runs `creep why` on the first finding a vulnerable twin reported.
func e2eWhy(t *testing.T, runs []e2eScan) e2eStep {
	t.Helper()
	for _, r := range runs {
		if r.Variant != "vulnerable" || r.firstID == "" {
			continue
		}
		t.Chdir(r.repo)
		return e2eRun(nil, "why", r.firstID)
	}
	return e2eStep{Command: "creep why", Exit: e2eNotRun, Lines: []string{"not run: no scan reported a finding on a vulnerable twin"}}
}

// e2eRepo copies tw into a fresh directory and makes it the working one.
func e2eRepo(t *testing.T, tw e2eTwin) string {
	t.Helper()
	repo := t.TempDir()
	copyTree(t, tw.dir, repo)
	t.Chdir(repo)
	return repo
}

func e2eExec(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// e2eRun runs one command and keeps the lines keep selects (all when nil).
func e2eRun(keep func(string) bool, args ...string) e2eStep {
	code, stdout, stderr := e2eExec(args...)
	step := e2eStep{Command: "creep " + strings.Join(args, " "), Exit: code}
	for line := range strings.Lines(stdout + stderr) {
		line = strings.TrimRight(line, "\r\n")
		if line != "" && (keep == nil || keep(line)) {
			step.Lines = append(step.Lines, line)
		}
	}
	return step
}

func isModelLine(line string) bool {
	return strings.HasPrefix(line, "model:") || strings.HasPrefix(line, "warning: model:")
}

func isTierRow(line string) bool {
	return slices.ContainsFunc([]string{"tier", "S ", "M ", "L "}, func(p string) bool { return strings.HasPrefix(line, p) })
}

// lastScanLine is the last line scan printed under its own prefix: the
// error that ended the run comes after the notices (consent, volume).
func lastScanLine(stderr string) string {
	last := ""
	for line := range strings.Lines(stderr) {
		if strings.HasPrefix(line, "creep scan") {
			last = strings.TrimSpace(line)
		}
	}
	return last
}

// readE2EReport reads the run's report.json, or nil when the run wrote none.
func readE2EReport(t *testing.T, repo string) *report.Report {
	t.Helper()
	f, err := os.Open(filepath.Join(repo, stateDir, "report.json"))
	if err != nil {
		return nil
	}
	defer f.Close()
	rep, err := report.ReadJSON(f)
	if err != nil {
		t.Errorf("%s: %v", repo, err)
		return nil
	}
	return rep
}
