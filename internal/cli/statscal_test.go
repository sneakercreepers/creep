package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// --stats counts calibration's own cost apart (#363): only calibrate-*
// requests, their sent tokens and the calibrate phase's time; a cached
// calibration shows no calls.
func TestRunStatsCalibrationCost(t *testing.T) {
	usage := func([]byte) (gateway.Usage, bool) { return gateway.Usage{InputTokens: 500, OutputTokens: 20}, true }
	ok := func(context.Context, gateway.Call) (*gateway.Reply, error) { return &gateway.Reply{Status: 200}, nil }
	tests := []struct {
		name     string
		purposes []string
		want     string
	}{
		{"cached", []string{"discover", "reader"}, "calibration: no model calls (cached or not run), 1s"},
		{"measured", []string{"calibrate-task", "calibrate-task", "calibrate-tool", "calibrate-context", "discover"},
			"calibration: 4 requests (4 sent), 2000 tokens in, 80 out, 1s"},
		{"look-alike purpose", []string{"calibrated", "recalibrate-task"}, "calibration: no model calls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := newRunStats(tickingClock())
			done := st.start(phaseCalibrate)
			send := st.countRequests(st.countSent(ok))
			for _, p := range tt.purposes {
				_, _ = send(context.Background(), gateway.Call{Purpose: p, Usage: usage})
			}
			done()
			var b bytes.Buffer
			st.print(&b, pricing{})
			if !strings.Contains(b.String(), tt.want) {
				t.Errorf("stats lack %q:\n%s", tt.want, b.String())
			}
		})
	}
}
