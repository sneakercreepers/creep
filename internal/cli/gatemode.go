package cli

import (
	"fmt"
	"io"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/report"
)

// runGate is the gate that judges one scan (#28, ADR 0021): the mode, how
// it was chosen, and that mode's gates.* value with the layer that set it.
type runGate struct {
	mode   config.ModeChoice
	value  string
	source string
}

// chooseGate picks the scan's mode from --mode or the CI environment and
// reads that mode's gate from the resolved layers.
func chooseGate(e env, r *config.Resolved) (runGate, error) {
	mode, err := chooseMode(e)
	if err != nil {
		return runGate{}, err
	}
	value, source := r.Gate(mode.Mode)
	return runGate{mode: mode, value: value, source: source}, nil
}

func chooseMode(e env) (config.ModeChoice, error) {
	getenv := e.deps.getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	return config.ChooseMode(e.opts.mode, getenv)
}

func (g runGate) nightly() bool { return g.mode.Mode == config.ModeNightly }

// verifies reports whether the scan builds the app and runs PoCs: only a
// nightly scan does, so a pull request scan never waits for verified
// findings, and its gate reads probable ones (#28). A pull request scan
// with sandbox.enabled says so on w.
func (g runGate) verifies(w io.Writer) bool {
	if !g.nightly() {
		fmt.Fprintln(w, "verification: pr mode builds no app and runs no PoC, so findings stay probable; --mode nightly verifies")
	}
	return g.nightly()
}

// judging prints the gate line on w and returns the gate the findings are
// judged by. A nightly scan whose verification did not try every finding
// it should have (sandbox off or unavailable, or a PoC not run) is judged
// at probable with the gate's severity (config.UnverifiedGate), so a
// finding nothing could verify fails the run instead of passing it as
// unverified (ADR 0021).
func (g runGate) judging(w io.Writer, v report.Verification) (string, error) {
	line := fmt.Sprintf("gate: %s mode (%s): %s %q (%s)", g.mode.Mode, g.mode.Source, config.GateKey(g.mode.Mode), g.value, g.source)
	why := unverifiedReason(v)
	if !g.nightly() || why == "" {
		fmt.Fprintln(w, escapeControl(line))
		return g.value, nil
	}
	gate, err := config.UnverifiedGate(g.value)
	if err != nil {
		return "", err
	}
	if gate != g.value {
		line += fmt.Sprintf(" read as %q: %s", gate, why)
	}
	fmt.Fprintln(w, escapeControl(line))
	return gate, nil
}

// unverifiedReason says why a nightly scan's verification did not try
// every finding it should have, or "" when it did. A PoC that ran and
// never verified counts as tried: its finding stays probable, which the
// nightly gate does not read (ADR 0020, ADR 0021).
func unverifiedReason(v report.Verification) string {
	switch {
	case v.Status == report.VerificationOff:
		return "verification did not run (sandbox.enabled is false)"
	case v.Status == report.VerificationUnavailable:
		return "verification unavailable (" + v.Reason + ")"
	case v.PoCs.NotRun > 0:
		return fmt.Sprintf("%d probable findings got no PoC run", v.PoCs.NotRun)
	}
	return ""
}
