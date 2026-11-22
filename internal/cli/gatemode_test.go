package cli

import (
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/sandbox"
)

// ciEnv is a CI environment for deps.getenv.
func ciEnv(vars map[string]string) func(string) string {
	return func(name string) string { return vars[name] }
}

var (
	scheduledRun   = map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "schedule"}
	pullRequestRun = map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request"}
)

// Protection, acceptance (#28): a pull request scan never waits for
// verified findings. With sandbox.enabled and a usable runtime, PR mode,
// chosen by default, by --mode pr or by a pull_request event, opens no
// sandbox, builds nothing and runs no PoC, and its gate reads probable
// findings. The nightly row proves the fake would see a build.
func TestPRModeNeverWaitsForVerification(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		env    map[string]string
		opened int
		gate   string
	}{
		{"default", nil, nil, 0, `gate: pr mode (default): gates.pr "probable:critical" (default)`},
		{"--mode pr", []string{"--mode", "pr"}, scheduledRun, 0, `gate: pr mode (flag --mode): gates.pr "probable:critical"`},
		{"pull_request event", nil, pullRequestRun, 0, `gate: pr mode (default)`},
		{"nightly builds", []string{"--mode", "nightly"}, nil, 1, `gate: nightly mode (flag --mode): gates.nightly "verified:high"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := &fakeBuilder{app: sandbox.App{Unavailable: sandbox.BuildNoFile}}
			opened := 0
			deps := withBuilder(fakeDeps(&fakeModel{verdict: sqliVulnerable}, calibrate.TierM), fb, nil, &opened)
			deps.getenv = ciEnv(tt.env)
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, sandboxOn)
			code, stdout, stderr := runScanWith(deps, append([]string{"--config", cfg, "scan"}, tt.args...)...)
			if code != exitcode.GateExceeded {
				t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
			}
			if opened != tt.opened || fb.builds != tt.opened || fb.exchanges != 0 {
				t.Errorf("opened %d, builds %d, exchanges %d, want %d opens", opened, fb.builds, fb.exchanges, tt.opened)
			}
			assertContains(t, "stderr", stderr, []string{tt.gate})
			if tt.opened == 0 {
				assertContains(t, "stderr", stderr, []string{"verification: pr mode builds no app and runs no PoC"})
				if strings.Contains(stdout+stderr, "sandbox:") {
					t.Errorf("a pr scan reported the sandbox:\n%s%s", stdout, stderr)
				}
			}
			assertAllProbable(t)
		})
	}
}

// Protection (#28, ADR 0021): a nightly scan whose sandbox did not verify
// never passes on findings nothing verified. The SSRF finding is rated
// high: the PR gate (probable:critical) passes it, and the nightly gate
// (verified:high) would pass it unverified, so without verification the
// nightly gate is read as probable:high and the run fails. With the app
// built, SSRF has no PoC template, so no run could verify it: it is read at
// probable too. TestNightlyBaselineAcceptsUnverifiable shows how an
// accepted one stops failing the run.
func TestNightlyNeverPassesUnverified(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		user    string
		checked []sandbox.Status
		fb      fakeBuilder
		code    int
		want    string // in stderr
	}{
		{"pr mode passes a high finding", "pr", "", nil, fakeBuilder{}, exitcode.OK, `gates.pr "probable:critical" (default)`},
		{"sandbox off", "nightly", "", nil, fakeBuilder{}, exitcode.GateExceeded,
			`gates.nightly "verified:high" (default) read as "probable:high": verification did not run (sandbox.enabled is false)`},
		{"no runtime", "nightly", sandboxOn, []sandbox.Status{missingDocker, missingPodman}, fakeBuilder{}, exitcode.GateExceeded,
			`read as "probable:high": verification unavailable (no_runtime)`},
		{"build failed", "nightly", sandboxOn, []sandbox.Status{rootlessDocker}, fakeBuilder{app: sandbox.App{Unavailable: sandbox.BuildFailed, Detail: "exit_1"}}, exitcode.GateExceeded,
			`read as "probable:high": verification unavailable (build_failed)`},
		{"operator loosened the nightly gate", "nightly", "gates:\n  nightly: none\n", nil, fakeBuilder{}, exitcode.OK, `gates.nightly "none" (--config`},
		{"app built, no template for the class", "nightly", sandboxOn, []sandbox.Status{rootlessDocker}, fakeBuilder{app: builtApp, port: 5000}, exitcode.GateExceeded,
			`gates.nightly "verified:high" (default); gates.pr "probable:critical" (default) also applies; a finding with no PoC template is read at probable` + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opened := 0
			deps := withBuilder(fakeDeps(&fakeModel{verdict: map[string]string{"ssrf": "vulnerable"}}, calibrate.TierM), &tt.fb, nil, &opened)
			deps.sandbox.detect = withSandbox(deps, tt.checked, nil, nil).sandbox.detect
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, tt.user)
			code, stdout, stderr := runScanWith(deps, "--config", cfg, "scan", "--mode", tt.mode)
			if code != tt.code {
				t.Fatalf("exit %d, want %d\n%s%s", code, tt.code, stdout, stderr)
			}
			assertContains(t, "stdout", stdout, []string{"probable  ssrf"})
			assertContains(t, "stderr", stderr, []string{tt.want})
		})
	}
}

// Protection (#28, ADR 0020, ADR 0021): a nightly scan never passes a
// finding a pr scan fails. The probable critical SQL injection fails
// gates.pr; in a nightly scan gates.pr applies too, so neither an operator
// gate that reads verified findings only nor a nightly gate turned off lets
// it pass. TestZeroRunsStayProbable covers a PoC the app made fail.
func TestNightlyNeverLooserThanPR(t *testing.T) {
	tests := []struct {
		name string
		mode string
		user string
		want string // in stderr
	}{
		{"pr fails it", "pr", "", `gates.pr "probable:critical" (default)`},
		{"nightly reads gates.pr too", "nightly", "gates:\n  nightly: verified:critical\n", `; gates.pr "probable:critical" (default) also applies`},
		{"nightly gate off", "nightly", "gates:\n  nightly: none\n", `gates.nightly "none" (--config`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := fakeDeps(&fakeModel{verdict: map[string]string{"sql_injection": "vulnerable"}}, calibrate.TierM)
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, tt.user)
			code, stdout, stderr := runScanWith(deps, "--config", cfg, "scan", "--mode", tt.mode)
			if code != exitcode.GateExceeded {
				t.Fatalf("exit %d, want %d\n%s%s", code, exitcode.GateExceeded, stdout, stderr)
			}
			assertContains(t, "stderr", stderr, []string{tt.want})
		})
	}
}

// Acceptance (#28, ADR 0007): a nightly scan that could not verify and
// left a file unread exits 4, not 1: an incomplete run wins over the
// gate, also when the unverified nightly gate trips.
func TestNightlyIncompleteWinsOverGate(t *testing.T) {
	deps := fakeDeps(&fakeModel{verdict: map[string]string{"ssrf": "vulnerable"}}, calibrate.TierM)
	cfg := scanRepo(t, map[string]string{"app.py": "@flask", "big.go": tooLarge}, "")
	code, stdout, stderr := runScanWith(deps, "--config", cfg, "scan", "--mode", "nightly")
	if code != exitcode.Incomplete {
		t.Fatalf("exit %d, want %d\n%s%s", code, exitcode.Incomplete, stdout, stderr)
	}
	assertContains(t, "stderr", stderr, []string{`read as "probable:high"`})
	assertContains(t, "stdout", stdout, []string{"probable  ssrf", "too_large"})
}

// Acceptance (#28, ADR 0021, ADR 0022): an unverifiable finding that fails
// a nightly scan stops failing it once a baseline entry suppresses it, and
// the entry does not hide it from the report.
func TestNightlyBaselineAcceptsUnverifiable(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	deps := baselineDeps(&fakeModel{verdict: map[string]string{"ssrf": "vulnerable"}}, baselineToday)
	code, _, stderr := runScanWith(deps, "scan", "--config", cfg, "--mode", "nightly", "--baseline", "b.json", "--baseline-write")
	if code != exitcode.GateExceeded {
		t.Fatalf("write exit %d: %s", code, stderr)
	}
	code, stdout, stderr := runScanWith(deps, "scan", "--config", cfg, "--mode", "nightly", "--baseline", "b.json")
	if code != exitcode.OK {
		t.Fatalf("baselined exit %d\n%s%s", code, stdout, stderr)
	}
	assertContains(t, "stdout", stdout, []string{"ssrf", "suppressed: baseline until"})
}

// Protection (#28, #61, #62): the scanned repository cannot loosen the
// gate of the mode that judges it, nor pick the mode. Under the operator's
// policy and with no --config, a project gates.nightly looser than the
// built-in or the user's gate, or a mode key, is a config error (exit 2)
// before any model call; a stricter one applies. The operator's own user
// file may loosen it, which proves the check reads the layer.
func TestProjectFileCannotLoosenNightlyGate(t *testing.T) {
	tests := []struct {
		name          string
		user, project string
		code          int
		want          string // in stderr
	}{
		{"built-in gate: unverified high fails", "", "", exitcode.GateExceeded, `read as "probable:high"`},
		{"project disables the nightly gate", "", "gates:\n  nightly: none\n", exitcode.ConfigError,
			`project "creep.yaml": gates.nightly "none" is looser than the built-in floor "verified:high"`},
		{"project raises the severity", "", "gates:\n  nightly: verified:critical\n", exitcode.ConfigError, `gates.nightly "verified:critical" is looser`},
		{"project restores the built-in over the user gate", "gates:\n  nightly: probable:medium\n", "gates:\n  nightly: verified:high\n", exitcode.ConfigError,
			`gates.nightly "verified:high" is looser than the gate "probable:medium" set by user "~/.creep/config.yaml"`},
		{"project picks the mode", "", "mode: pr\n", exitcode.ConfigError, `unknown key "mode"`},
		{"project picks the pr gate for nightly", "", "gates:\n  pr: none\n", exitcode.ConfigError, `gates.pr "none" is looser`},
		{"project stricter: applies", "", "gates:\n  nightly: probable:high\n", exitcode.GateExceeded, `gates.nightly "probable:high" (project "creep.yaml")`},
		{"operator loosens: applies", "gates:\n  nightly: none\n", "", exitcode.OK, `gates.nightly "none" (user "~/.creep/config.yaml")`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"app.py": "@flask"}
			if tt.project != "" {
				files["creep.yaml"] = tt.project
			}
			scanRepo(t, files, "")
			setOperatorPolicy(t)
			if tt.user != "" {
				writeUserConfig(t, tt.user)
			}
			m := &fakeModel{verdict: map[string]string{"ssrf": "vulnerable"}}
			code, stdout, stderr := runScanWith(limitDeps(m), "scan", "--mode", "nightly")
			if code != tt.code {
				t.Fatalf("exit %d, want %d\n%s%s", code, tt.code, stdout, stderr)
			}
			assertContains(t, "stderr", stderr, []string{tt.want})
			if code == exitcode.ConfigError && m.calls != 0 {
				t.Errorf("%d model calls before the config error", m.calls)
			}
		})
	}
}

// Acceptance (#28): the policy's limits apply per mode. Each mode reads
// its own key, floored by its own limit: a user gate looser than either
// limit is a config error in both modes, and each mode's gate line names
// the policy default it reads.
func TestPolicyLimitsApplyPerMode(t *testing.T) {
	const policy = "defaults:\n  model:\n    contract: openai\n    endpoint: https://models.example.invalid/v1\n    name: test-model\n" +
		"  gates:\n    pr: probable:high\n    nightly: verified:medium\nlimits:\n  gates:\n    pr: probable:high\n    nightly: verified:medium\n"
	tests := []struct {
		name, mode, user string
		code             int
		want             string
	}{
		{"pr reads its limit-floored gate", "pr", "", exitcode.GateExceeded, `gates.pr "probable:high" (policy`},
		{"nightly reads its own", "nightly", "", exitcode.GateExceeded, `gates.nightly "verified:medium" (policy`},
		{"nightly unverified stays at the limit's severity", "nightly", "", exitcode.GateExceeded, `read as "probable:medium"`},
		{"loose nightly refused in pr mode", "pr", "gates:\n  nightly: verified:high\n", exitcode.ConfigError, `gates.nightly "verified:high" is looser than the limit "verified:medium"`},
		{"loose nightly refused in nightly mode", "nightly", "gates:\n  nightly: verified:high\n", exitcode.ConfigError, `is looser than the limit "verified:medium"`},
		{"loose pr refused in nightly mode", "nightly", "gates:\n  pr: probable:critical\n", exitcode.ConfigError, `gates.pr "probable:critical" is looser than the limit "probable:high"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			t.Setenv(policyEnv, writeOutside(t, "org.yaml", policy))
			if tt.user != "" {
				writeUserConfig(t, tt.user)
			}
			m := &fakeModel{verdict: map[string]string{"ssrf": "vulnerable"}}
			code, stdout, stderr := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--mode", tt.mode)
			if code != tt.code {
				t.Fatalf("exit %d, want %d\n%s%s", code, tt.code, stdout, stderr)
			}
			assertContains(t, "stderr", stderr, []string{tt.want})
		})
	}
}

// config explain shows the mode, how it was chosen and the gate it reads
// with that gate's key and layer (#28).
func TestExplainShowsModeGate(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
		want []string
	}{
		{"default", nil, nil, []string{`mode "pr" default`, `gate "probable:critical" gates.pr, default`}},
		{"schedule", nil, scheduledRun, []string{`mode "nightly" GitHub Actions schedule event`, `gate "verified:low" gates.nightly, user "~/.creep/config.yaml"`, `gate "probable:critical" gates.pr, default`}},
		{"flag over schedule", []string{"--mode", "pr"}, scheduledRun, []string{`mode "pr" flag --mode`, `gate "probable:critical" gates.pr, default`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configEnv(t, "", "gates:\n  nightly: verified:low\n", "")
			deps := noModelDeps
			deps.getenv = ciEnv(tt.env)
			code, stdout, stderr := runScanWith(deps, append([]string{"config", "explain"}, tt.args...)...)
			if code != exitcode.OK {
				t.Fatalf("exit %d\n%s", code, stderr)
			}
			assertContains(t, "stdout", squeezeColumns(stdout), tt.want)
		})
	}
}

// squeezeColumns joins each line's fields with one space, so a check does
// not depend on the table's column widths.
func squeezeColumns(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.Join(strings.Fields(l), " ")
	}
	return strings.Join(lines, "\n")
}

func TestInvalidModeIsUsageError(t *testing.T) {
	for _, args := range [][]string{{"--mode", "weekly"}, {"--mode="}, {"--mode", "NIGHTLY"}} {
		code, _, stderr := run(append([]string{"config", "explain"}, args...)...)
		if code != exitcode.ConfigError || !strings.Contains(stderr, "invalid --mode") {
			t.Errorf("%q: exit %d\n%s", args, code, stderr)
		}
	}
}

func TestProductionReadsCIEnvironment(t *testing.T) {
	if productionDeps().getenv == nil {
		t.Fatal("productionDeps has no getenv, so a scheduled run would never be nightly")
	}
}
