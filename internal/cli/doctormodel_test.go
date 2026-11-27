package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
)

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

// Acceptance (#362, ADR 0034): creep doctor contacts the model through
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
		{"unreachable", &fakeModel{fail: map[string]error{"discover": errors.New("connection refused")}}, calibrate.TierS, errors.New("not cached"), exitcode.ModelOrSandbox, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
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
				if bytes.Contains(p, []byte("flask")) || bytes.Contains(p, []byte("app.py")) {
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
