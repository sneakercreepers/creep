package cli

import (
	"errors"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

// Acceptance (#175): a recorded run replays to the same scan output and
// exit code with zero model calls. Recordings use the state cache format
// (#8, as the reader fixtures of #200), signed with this user's secret.
func TestScanReplay(t *testing.T) {
	tests := []struct {
		name     string
		verdict  map[string]string
		wantCode int
	}{
		{"gate exceeded", map[string]string{"sql_injection": "vulnerable"}, exitcode.GateExceeded},
		{"incomplete", map[string]string{"ssrf": "inconclusive"}, exitcode.Incomplete},
		{"clean", nil, exitcode.OK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			recorder := &fakeModel{verdict: tt.verdict}
			code, recorded, errOut := runScanWith(fakeDeps(recorder, calibrate.TierM), "scan", "--record", "--config", cfg)
			if code != tt.wantCode || recorder.calls == 0 {
				t.Fatalf("record: exit %d after %d calls\n%s\n%s", code, recorder.calls, recorded, errOut)
			}
			offline := &fakeModel{fail: map[string]error{}}
			for _, class := range []string{"sql_injection", "ssrf", "path_traversal", "command_injection", "template_injection", "nosql_injection"} {
				offline.fail[class] = errors.New("replay must not call the model")
			}
			code, replayed, errOut := runScanWith(fakeDeps(offline, calibrate.TierM), "scan", "--replay", "--config", cfg)
			if offline.calls != 0 {
				t.Fatalf("replay made %d model calls", offline.calls)
			}
			if code != tt.wantCode || replayed != recorded {
				t.Fatalf("replay: exit %d, want %d\nrecorded:\n%s\nreplayed:\n%s\nstderr: %s", code, tt.wantCode, recorded, replayed, errOut)
			}
		})
	}
}

// Replay never falls back to the model: a request with no recording ends
// the run as send_failed (exit 4), it is not sent.
func TestScanReplayWithoutRecording(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	m := &fakeModel{}
	code, out, _ := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--replay", "--config", cfg)
	if code != exitcode.Incomplete || m.calls != 0 {
		t.Fatalf("exit %d after %d calls, want 4 after 0\n%s", code, m.calls, out)
	}
}
