package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
)

// doctorMarker is planted as a repository file's name and content; no
// doctor probe or egress.log may hold it.
const doctorMarker = "zq7doctormarkerx9"

var probeNeedle = regexp.MustCompile(`let (marker_[a-z_]+) = "([a-z0-9-]+)";`)

// contextAnswer answers a context probe: the needle's value, or, with
// cut, what a model that never saw the first line would say.
func contextAnswer(body []byte, cut bool) (map[string]any, bool) {
	user := userContent(body)
	if !strings.Contains(user, "Question: what string is assigned to") {
		return nil, false
	}
	m := probeNeedle.FindStringSubmatch(user)
	if m == nil || cut {
		return map[string]any{"value": "none"}, true
	}
	return map[string]any{"value": m[2]}, true
}

// Acceptance (#362, ADR 0035): creep doctor contacts the model through
// the run's link with two synthetic probes and reports reachability,
// schema and canary, and usable context against the tier; a bad reply or
// a short context warns with exit 0, an unreachable model exits 3, and no
// repository file reaches any call.
func TestDoctorProbesTheModel(t *testing.T) {
	tests := []struct {
		name  string
		model *fakeModel
		tier  calibrate.Tier
		cal   error
		code  int
		want  []string
	}{
		{"healthy, not calibrated", &fakeModel{}, calibrate.TierS, errors.New("not cached"), exitcode.OK,
			[]string{"model: reachable; a synthetic tier S discovery batch", "usable context holds the 10 KiB a tier S discovery call needs (tier S until the first scan calibrates)"}},
		{"healthy at the cached tier", &fakeModel{}, calibrate.TierM, nil, exitcode.OK,
			[]string{"tier M discovery batch", "a tier M discovery call needs (calibrated tier)"}},
		{"canary missed", &fakeModel{missCanary: true}, calibrate.TierS, errors.New("not cached"), exitcode.OK,
			[]string{"warning: model: the reply to a synthetic tier S discovery batch missed the discovery canary", "exit 4"}},
		{"short context", &fakeModel{shortContext: true}, calibrate.TierS, errors.New("not cached"), exitcode.OK,
			[]string{"warning: model: usable context is below", "probe: wrong_answer", "num_ctx 16384"}},
		{"consent refused", &fakeModel{fail: map[string]error{"discover": &gateway.ConsentError{Endpoint: "https://models.example.invalid", Err: gateway.ErrNoConsent}}}, calibrate.TierS, errors.New("not cached"), exitcode.ConfigError, nil},
		{"unreachable", &fakeModel{fail: map[string]error{"discover": errors.New("connection refused")}}, calibrate.TierS, errors.New("not cached"), exitcode.ModelOrSandbox, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask", doctorMarker + ".py": doctorMarker}, "")
			deps := fakeDeps(tt.model, tt.tier)
			deps.calibrate = fixedCalibration(tt.tier, tt.cal)
			var payloads [][]byte
			connect := deps.connect
			deps.connect = func(r *config.Resolved, dir string, w io.Writer) (modelLink, error) {
				link, err := connect(r, dir, w)
				send := link.send
				link.send = func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
					payloads = append(payloads, c.Payload)
					return send(ctx, c)
				}
				return link, err
			}
			code, stdout, stderr := runScanWith(deps, "--config", cfg, "doctor")
			for _, p := range payloads {
				if bytes.Contains(p, []byte(doctorMarker)) || bytes.Contains(p, []byte("flask")) || bytes.Contains(p, []byte("app.py")) {
					t.Fatal("a doctor probe carried repository text")
				}
			}
			if code != tt.code {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, tt.code, stdout, stderr)
			}
			assertContains(t, "stdout", stdout, tt.want)
			if tt.model.calls == 0 || tt.model.calls > 4 {
				t.Errorf("%d model calls, want the two probes (and a retry each)", tt.model.calls)
			}
		})
	}
}

// Protection (#362, ADR 0035): with a model CLI, doctor's probes go
// through the gateway after the tool canary and egress.log logs them;
// neither the CLI's input nor egress.log holds repository text, and a CLI
// that fails the canary exits 3 and gets no probe.
func TestDoctorCommandProbes(t *testing.T) {
	tests := []struct {
		mode   string
		code   int
		probed bool
	}{
		{"answer", exitcode.OK, true},
		{"obey", exitcode.ModelOrSandbox, false},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			cfg, prompts := commandScan(t, tt.mode, "")
			if err := os.WriteFile(doctorMarker+".py", []byte(doctorMarker+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runScanWith(commandDeps(), "--config", cfg, "doctor")
			if code != tt.code {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, tt.code, stdout, stderr)
			}
			egress := doctorEgress(t)
			for _, body := range append(savedPrompts(t, prompts), egress) {
				if strings.Contains(body, doctorMarker) || strings.Contains(body, "app.py") {
					t.Fatal("a doctor call or egress.log holds repository text")
				}
			}
			if probed := strings.Contains(egress, `"purpose":"doctor.discover"`); probed != tt.probed {
				t.Errorf("discovery probe logged = %v, want %v:\n%s", probed, tt.probed, egress)
			}
		})
	}
}

// doctorEgress reads the one egress.log doctor wrote.
func doctorEgress(t *testing.T) string {
	t.Helper()
	logs, _ := filepath.Glob(filepath.Join(".creep", "runs", "*", "egress.log"))
	if len(logs) != 1 {
		t.Fatalf("egress logs = %v", logs)
	}
	data, err := os.ReadFile(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
