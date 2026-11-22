package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

// actionStandInEnv turns this test binary into creep for the Action's
// self-test (ci.yml job action, ADR 0023). That job runs action.yml before
// any release holds the code under review, so there is no binary to
// download and verify, and a production binary needs a real model:
// --replay serves only recordings signed by the runner's own state key.
// With the variable set, the binary runs the real CLI (walk, discovery,
// planner, reader, reports, exit code, every config layer including the
// project file) with the fake model and fixed calibration the protection
// tests use, so nothing reaches a network. The value is the verdict for
// every sql_injection hypothesis. Only `go test -c` builds it, so creep
// itself has no such switch.
const actionStandInEnv = "CREEP_ACTION_STANDIN"

func actionStandIn(verdict string, args []string, stdout, stderr io.Writer) int {
	if verdict != "vulnerable" && verdict != "not_vulnerable" {
		fmt.Fprintf(stderr, "%s must be vulnerable or not_vulnerable\n", actionStandInEnv)
		return exitcode.ConfigError
	}
	m := &fakeModel{verdict: map[string]string{"sql_injection": verdict}}
	return runWith(args, stdout, stderr, limitDeps(m))
}

// actionSelfTestPolicy is the policy the ci.yml action job writes: the
// operator's model, outside the sample repository.
const actionSelfTestPolicy = "defaults:\n  model:\n    contract: openai\n    endpoint: https://models.example.invalid/v1\n    name: test-model\n"

// The self-test's three samples must end the way the job asserts, or the
// job would pass for the wrong reason: the vulnerable one over the gate
// (1), the clean one at 0 and the one whose creep.yaml lowers
// budget.max_calls to 1 incomplete (4, which the Action must fail like 1).
// Each run that scanned writes every report the Action consumes.
func TestActionStandIn(t *testing.T) {
	app, err := os.ReadFile(filepath.Join("testdata", "action", "app.py"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		verdict  string
		project  string
		wantCode int
	}{
		{"vulnerable sample fails the gate", "vulnerable", "", exitcode.GateExceeded},
		{"clean sample passes", "not_vulnerable", "", exitcode.OK},
		{"starved sample is incomplete", "vulnerable", "budget:\n  max_calls: 1\n", exitcode.Incomplete},
		{"unknown verdict scans nothing", "maybe", "", exitcode.ConfigError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"app.py": string(app)}
			if tt.project != "" {
				files["creep.yaml"] = tt.project
			}
			scanRepo(t, files, "")
			t.Setenv(policyEnv, writeOutside(t, "policy.yaml", actionSelfTestPolicy))
			t.Setenv("GITHUB_ACTIONS", "true")
			var out, errOut bytes.Buffer
			code := actionStandIn(tt.verdict, []string{"scan"}, &out, &errOut)
			if code != tt.wantCode {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, tt.wantCode, out.String(), errOut.String())
			}
			checkActionReports(t, code != exitcode.ConfigError)
		})
	}
}

func checkActionReports(t *testing.T, want bool) {
	t.Helper()
	for _, name := range []string{"report.json", "report.sarif", "report.md"} {
		info, err := os.Lstat(filepath.Join(".creep", name))
		if got := err == nil && info.Mode().IsRegular(); got != want {
			t.Errorf(".creep/%s written: %v, want %v (%v)", name, got, want, err)
		}
	}
}
