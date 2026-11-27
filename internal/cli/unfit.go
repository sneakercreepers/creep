package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/report"
)

// unfitCommands are the commands --allow-unfit-model changes. Any other
// one refuses it rather than ignore it: creep mcp in particular, so an
// agent can never scan past the floor (ADR 0036).
var unfitCommands = map[string]bool{"scan": true, "resume": true}

func checkUnfitFlag(command string, o globalOptions) error {
	if o.allowUnfit && !unfitCommands[command] {
		return fmt.Errorf("--allow-unfit-model changes only scan and resume, not %s", command)
	}
	if o.allowUnfit && o.baselineWrite {
		// A baseline would accept an unreliable run's findings for later scans.
		return errors.New("--allow-unfit-model cannot be combined with --baseline-write")
	}
	return nil
}

// fitOrAllowed refuses an unfit calibration (exit 3 through failureCode)
// unless --allow-unfit-model was passed; with it, it warns on stderr and
// the report labels every model finding unreliable_model.
func (s *session) fitOrAllowed(stderr io.Writer, cal calibrate.Calibration) error {
	err := cal.CheckFit()
	if err == nil {
		return nil
	}
	if !s.opts.allowUnfit {
		return err
	}
	fmt.Fprintf(stderr, "creep scan: warning: %s\n", escapeControl(err.Error()))
	return nil
}

// labelUnreliable marks every finding the model's answers decided or left
// undecided. Scanner findings (gitleaks, osv-scanner) are not the model's
// and are left as they are.
func labelUnreliable(cal calibrate.Calibration, findings []report.Finding) {
	if cal.Fitness.Fit {
		return
	}
	for i := range findings {
		findings[i].UnreliableModel = true
	}
}
