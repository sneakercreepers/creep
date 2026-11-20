package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/sandbox"
)

var (
	rootlessDocker  = sandbox.Status{Runtime: sandbox.Docker, Path: "/usr/bin/docker", Reachable: true, Rootless: true, Isolation: sandbox.IsolationRootless, Reason: sandbox.ReasonOK}
	endpointDocker  = sandbox.Status{Runtime: sandbox.Docker, Path: "/usr/bin/docker", Host: "unix:///run/user/1000/docker.sock", Reachable: true, Rootless: true, Isolation: sandbox.IsolationRootless, Reason: sandbox.ReasonOK}
	hostileEndpoint = sandbox.Status{Runtime: sandbox.Docker, Path: "/usr/bin/docker", Host: "tcp://x\x1b[2J", Reachable: true, Rootless: true, Isolation: sandbox.IsolationRootless, Reason: sandbox.ReasonOK}
	rootfulPodman   = sandbox.Status{Runtime: sandbox.Podman, Path: "/usr/bin/podman", Reachable: true, Isolation: sandbox.IsolationRootful, Reason: sandbox.ReasonOK}
	missingDocker   = sandbox.Status{Runtime: sandbox.Docker, Isolation: sandbox.IsolationNone, Reason: sandbox.ReasonNotFound}
	missingPodman   = sandbox.Status{Runtime: sandbox.Podman, Isolation: sandbox.IsolationNone, Reason: sandbox.ReasonNotFound}
	downDocker      = sandbox.Status{Runtime: sandbox.Docker, Path: "/usr/bin/docker", Isolation: sandbox.IsolationNone, Reason: sandbox.ReasonNotRunning}
)

// withSandbox returns deps whose sandbox detector reports checked and
// whose cleaner counts per runtime, failing for fail.
func withSandbox(deps scanDeps, checked []sandbox.Status, removed map[sandbox.Runtime]sandbox.Removed, fail error) scanDeps {
	deps.sandbox = sandboxDeps{
		detect: func(_ context.Context, env sandbox.Env) sandbox.Report {
			if env.Repo == "" || env.Getenv == nil {
				return sandbox.Report{}
			}
			return sandbox.Report{Checked: checked}
		},
		clean: func(_ context.Context, st sandbox.Status) (sandbox.Removed, error) {
			return removed[st.Runtime], fail
		},
		images: func(_ context.Context, st sandbox.Status) []sandbox.PinnedImage {
			return []sandbox.PinnedImage{
				{Role: "canary", Ref: sandbox.CanaryImage, Present: true},
				{Role: "database", Ref: sandbox.DatabaseImage},
			}
		},
	}
	return deps
}

func TestProductionWiresSandbox(t *testing.T) {
	d := productionDeps().sandbox
	if d.detect == nil || d.clean == nil || d.images == nil || d.open == nil {
		t.Fatal("production deps leave the sandbox unchecked")
	}
}

// Acceptance (#21): creep doctor reports runtime, rootless status and
// isolation level, and a missing runtime is not an error.
func TestDoctorReportsSandbox(t *testing.T) {
	hostile := rootlessDocker
	hostile.Path = "/opt/\x1b[2Jdocker"
	tests := []struct {
		name    string
		checked []sandbox.Status
		config  string
		want    []string
		notWant []string
	}{
		{"rootless docker", []sandbox.Status{rootlessDocker, missingPodman}, "sandbox:\n  enabled: true\n",
			[]string{"sandbox runtime docker \"/usr/bin/docker\": usable, rootless yes, isolation rootless", "sandbox runtime podman: not usable (not_found)", "sandbox: runtime docker, rootless yes, isolation rootless", "findings stay probable"},
			[]string{"warning", "sandbox.enabled is false"}},
		// creep never pulls: a missing pinned image comes with the exact pull command.
		{"pinned images", []sandbox.Status{rootlessDocker}, "",
			[]string{"sandbox image canary " + sandbox.CanaryImage + ": present",
				"sandbox image database " + sandbox.DatabaseImage + ": missing; creep never pulls, run: docker pull " + sandbox.DatabaseImage},
			nil},
		// The pull goes to the endpoint creep checked, never a different daemon.
		{"pull to the checked endpoint", []sandbox.Status{endpointDocker}, "",
			[]string{"run: docker --host=unix:///run/user/1000/docker.sock pull " + sandbox.DatabaseImage}, []string{"\x1b"}},
		{"podman pulls locally", []sandbox.Status{missingDocker, rootfulPodman}, "",
			[]string{"run: podman --remote=false pull " + sandbox.DatabaseImage}, nil},
		{"hostile endpoint escaped", []sandbox.Status{hostileEndpoint}, "",
			[]string{`--host=tcp://x\x1b[2J pull`}, []string{"\x1b"}},
		{"rootful only warns", []sandbox.Status{downDocker, rootfulPodman}, "",
			[]string{"not usable (not_running)", "sandbox: runtime podman, rootless no, isolation rootful", "warning: the daemon runs as root", "sandbox.enabled is false"}, nil},
		{"no runtime", []sandbox.Status{missingDocker, missingPodman}, "",
			[]string{"sandbox: unavailable: no usable docker or podman; scans still run and findings stay probable"}, []string{"isolation rootless", "sandbox image"}},
		{"path escaped", []sandbox.Status{hostile}, "", []string{`\x1b[2Jdocker`}, []string{"\x1b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, nil, tt.config)
			code, stdout, stderr := runScanWith(withSandbox(noModelDeps, tt.checked, nil, nil), "--config", cfg, "doctor")
			if code != exitcode.OK {
				t.Fatalf("exit %d\n%s", code, stderr)
			}
			assertContains(t, "stdout", stdout, tt.want)
			for _, w := range tt.notWant {
				if strings.Contains(stdout, w) {
					t.Errorf("stdout contains %q:\n%s", w, stdout)
				}
			}
		})
	}
}

func TestDoctorWithoutDetectorSaysNotChecked(t *testing.T) {
	cfg := scanRepo(t, nil, "")
	code, stdout, _ := runScanWith(noModelDeps, "--config", cfg, "doctor")
	if code != exitcode.OK || !strings.Contains(stdout, "sandbox: not checked") {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
}

// Acceptance (#21): creep clean removes what a killed run left on every
// reachable runtime; one it cannot reach has nothing to remove, and a
// failed removal never exits 0.
func TestClean(t *testing.T) {
	tests := []struct {
		name     string
		checked  []sandbox.Status
		fail     error
		deps     func(scanDeps) scanDeps
		args     []string
		wantCode int
		want     []string
	}{
		{"removes orphans", []sandbox.Status{rootlessDocker, rootfulPodman}, nil, nil, nil, exitcode.OK,
			[]string{"docker: removed 3 creep container(s), 4 image(s) and 2 network(s)", "podman: removed 1 creep container(s), 0 image(s) and 0 network(s)"}},
		{"unreachable runtime", []sandbox.Status{downDocker, missingPodman}, nil, nil, nil, exitcode.OK,
			[]string{"docker: not reachable (not_running); nothing removed", "podman: not reachable (not_found)"}},
		{"removal fails", []sandbox.Status{rootlessDocker}, errors.New("rm: \x1b[31mdenied"), nil, nil, exitcode.ModelOrSandbox,
			[]string{`creep clean: docker: rm: \x1b[31mdenied`}},
		{"no driver fails closed", nil, nil, func(d scanDeps) scanDeps { d.sandbox = sandboxDeps{}; return d }, nil, exitcode.ModelOrSandbox,
			[]string{"no container runtime driver"}},
		{"arguments refused", nil, nil, nil, []string{"all"}, exitcode.ConfigError, []string{"unexpected arguments"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, nil, "")
			deps := withSandbox(noModelDeps, tt.checked, map[sandbox.Runtime]sandbox.Removed{sandbox.Docker: {Containers: 3, Images: 4, Networks: 2}, sandbox.Podman: {Containers: 1}}, tt.fail)
			if tt.deps != nil {
				deps = tt.deps(deps)
			}
			code, stdout, stderr := runScanWith(deps, append([]string{"--config", cfg, "clean"}, tt.args...)...)
			if code != tt.wantCode {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, tt.wantCode, stdout, stderr)
			}
			assertContains(t, "output", stdout+stderr, tt.want)
			if strings.Contains(stderr, "\x1b") {
				t.Errorf("stderr not escaped: %q", stderr)
			}
		})
	}
}

// Acceptance (#21): with the sandbox enabled and no runtime, a scan exits
// as it would without the sandbox and every finding stays probable.
func TestScanWithoutRuntimeStaysProbable(t *testing.T) {
	flask := map[string]string{"app.py": "@flask"}
	verdict := map[string]string{"sql_injection": "vulnerable"}
	cfg := scanRepo(t, flask, "")
	base, _, _ := runScanWith(fakeDeps(&fakeModel{verdict: verdict}, calibrate.TierM), "--config", cfg, "scan")

	data, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg = filepath.Join(t.TempDir(), "creep.yaml")
	if err := os.WriteFile(cfg, append(data, "sandbox:\n  enabled: true\n"...), 0o600); err != nil { //nolint:gosec // G703: in t.TempDir()
		t.Fatal(err)
	}
	deps := withSandbox(fakeDeps(&fakeModel{verdict: verdict}, calibrate.TierM), []sandbox.Status{missingDocker, missingPodman}, nil, nil)
	code, stdout, stderr := runScanWith(deps, "--config", cfg, "scan")
	if code != base || code != exitcode.GateExceeded {
		t.Fatalf("exit %d with the sandbox enabled, %d without (want %d)\n%s", code, base, exitcode.GateExceeded, stderr)
	}
	assertContains(t, "stdout", stdout, []string{"sandbox: verification unavailable (no_runtime); findings stay probable"})
	f, err := os.Open(filepath.Join(stateDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := report.ReadJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("no findings to check")
	}
	probable := 0
	for _, fd := range rep.Findings {
		if fd.Status == report.StatusVerified {
			t.Errorf("finding %s is verified without a sandbox", fd.ID)
		}
		if fd.Status == report.StatusProbable {
			probable++
		}
	}
	if probable == 0 {
		t.Errorf("no probable finding: %+v", rep.Findings)
	}
}
