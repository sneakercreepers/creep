package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/sneakercreepers/creep/internal/bench"
	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/gateway"
)

// calibrationCost is what calibration alone spent in a run (#363): its
// requests, those that reached the gateway, their tokens and the calibrate
// phase's wall time. A cached calibration makes no request.
type calibrationCost struct {
	Requests int
	Sent     int
	Usage    gateway.Usage
	Took     time.Duration
}

func isCalibration(c gateway.Call) bool {
	return strings.HasPrefix(c.Purpose, calibrate.PurposePrefix)
}

// calibrationCostLocked is the run's calibration cost; st.mu must be held.
func (st *runStats) calibrationCostLocked() calibrationCost {
	cost := st.cal
	for _, ph := range st.phases {
		if ph.name == phaseCalibrate {
			cost.Took += ph.took
		}
	}
	return cost
}

func (st *runStats) calibrationCost() calibrationCost {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.calibrationCostLocked()
}

func (c calibrationCost) text() string {
	if c.Requests == 0 {
		return fmt.Sprintf("no model calls (cached or not run), %s", c.Took.Round(time.Millisecond))
	}
	return fmt.Sprintf("%d requests (%d sent), %d tokens in, %d out, %s",
		c.Requests, c.Sent, c.Usage.InputTokens, c.Usage.OutputTokens, c.Took.Round(time.Millisecond))
}

// benchCost is c in creep bench's results, with what the calibration measured.
func (c calibrationCost) benchCost(r calibrate.Result) *bench.CalibrationCost {
	return &bench.CalibrationCost{
		Calls: c.Sent, InputTokens: c.Usage.InputTokens, OutputTokens: c.Usage.OutputTokens,
		Seconds: c.Took.Round(time.Second).Seconds(), Tier: string(r.Tier), Fit: r.Fitness.Fit, Unfit: string(r.Fitness.Reason),
	}
}
