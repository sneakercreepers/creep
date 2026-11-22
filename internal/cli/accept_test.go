package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/baseline"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
)

// acceptRepo writes a last-scan report holding findings into .creep of a
// fresh working directory.
func acceptRepo(t *testing.T, findings ...report.Finding) {
	t.Helper()
	isolateUserConfig(t)
	t.Chdir(t.TempDir())
	rep, err := report.New(report.Input{Findings: findings})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := report.WriteJSON(&b, rep); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(stateDir, "report.json"), b.String())
}

const acceptFingerprint = "0123456789abcdef0123456789abcdef"

func acceptable(id string, status report.Status) report.Finding {
	f := report.Finding{ID: id, Class: "sqli", Status: status, Path: "app/db.py", Line: 12}
	if status == report.StatusProbable || status == report.StatusVerified {
		f.Fingerprint = acceptFingerprint
	}
	return f
}

// Acceptance (#27): accept without a reason or an expiry is rejected, and
// so is anything a baseline must not suppress.
func TestAcceptRefuses(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no reason", []string{"accept", "p1", "--expires", "90d"}, "needs --expires <days>d and --reason"},
		{"no expiry", []string{"accept", "p1", "--reason", "admin only"}, "needs --expires <days>d and --reason"},
		{"empty reason", []string{"accept", "p1", "--expires", "90d", "--reason", ""}, "reason must be one printable line"},
		{"multi-line reason", []string{"accept", "p1", "--expires", "90d", "--reason", "ok\nFAKE"}, "reason must be one printable line"},
		{"expiry over the cap", []string{"accept", "p1", "--expires", "366d", "--reason", "r"}, "1d to 365d"},
		{"expiry as a date", []string{"accept", "p1", "--expires", "2099-01-01", "--reason", "r"}, "number of days"},
		{"zero days", []string{"accept", "p1", "--expires", "0d", "--reason", "r"}, "number of days"},
		{"not evaluated", []string{"accept", "n1", "--expires", "90d", "--reason", "r"}, "only a probable or verified finding"},
		{"discarded", []string{"accept", "d1", "--expires", "90d", "--reason", "r"}, "only a probable or verified finding"},
		{"unknown ID", []string{"accept", "x9", "--expires", "90d", "--reason", "r"}, "no finding x9"},
		{"bad ID", []string{"accept", "../x", "--expires", "90d", "--reason", "r"}, "valid finding ID"},
		{"two IDs", []string{"accept", "p1", "n1", "--expires", "90d", "--reason", "r"}, "exactly one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acceptRepo(t, acceptable("p1", report.StatusProbable), acceptable("n1", report.StatusNotEvaluated), acceptable("d1", report.StatusDiscarded))
			code, _, stderr := run(tt.args...)
			if code != exitcode.ConfigError || !strings.Contains(stderr, tt.want) {
				t.Errorf("exit %d, want 2 naming %q: %s", code, tt.want, stderr)
			}
			if _, err := os.Lstat(defaultBaselineFile); err == nil {
				t.Error("a refused accept wrote the baseline file")
			}
		})
	}
}

func TestAcceptWithoutReport(t *testing.T) {
	isolateUserConfig(t)
	t.Chdir(t.TempDir())
	code, _, stderr := run("accept", "p1", "--expires", "90d", "--reason", "r")
	if code != exitcode.ConfigError {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

// accept adds to an existing file, replaces the finding's baseline entry
// instead of doubling it, and refuses a malformed file rather than
// overwriting it.
func TestAcceptUpdatesFile(t *testing.T) {
	acceptRepo(t, acceptable("p1", report.StatusProbable))
	old := `{"version": 1, "entries": [{"kind": "baseline", "fingerprint": "` + acceptFingerprint + `", "class": "sqli", "path": "app/db.py", "expires": "2027-01-01"},` +
		`{"kind": "accepted", "fingerprint": "` + strings.Repeat("a", 32) + `", "class": "ssrf", "path": "b.py", "expires": "2027-01-01", "reason": "kept"}]}`
	mustWrite(t, "risks.json", old)
	code, stdout, stderr := run("accept", "p1", "--expires", "10d", "--reason", "admin only", "--baseline", "risks.json")
	if code != exitcode.OK || !strings.Contains(stdout, "accepted p1 (sqli, app/db.py:12)") {
		t.Fatalf("exit %d: %s%s", code, stdout, stderr)
	}
	data, err := os.ReadFile("risks.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := baseline.Parse(data, baselineToday)
	if err != nil || len(b.Entries) != 2 || b.Entries[0].Reason != "admin only" || b.Entries[1].Reason != "kept" {
		t.Fatalf("file %s, %v", data, err)
	}

	mustWrite(t, "broken.json", "{")
	if code, _, _ := run("accept", "p1", "--expires", "10d", "--reason", "r", "--baseline", "broken.json"); code != exitcode.ConfigError {
		t.Errorf("accept over a malformed file exit %d", code)
	}
	if data, _ := os.ReadFile("broken.json"); string(data) != "{" {
		t.Errorf("a malformed file was overwritten: %s", data)
	}
}
