package config

import (
	"fmt"
	"slices"
	"strings"
)

// Mode is the kind of scan a gate judges (design.md: CI gates, #28). A
// pull request scan has no sandbox, so gates.pr reads probable findings; a
// nightly scan verifies, so gates.nightly may read verified ones.
type Mode string

// The scan modes.
const (
	ModePR      Mode = "pr"
	ModeNightly Mode = "nightly"
)

// Modes lists the values --mode takes.
func Modes() []string { return []string{string(ModePR), string(ModeNightly)} }

// ModeChoice is a scan's mode and how it was chosen, as config explain and
// the scan's gate line show it.
type ModeChoice struct {
	Mode   Mode
	Source string
}

// Mode sources.
const (
	modeFromFlag     = "flag --mode"
	modeFromSchedule = "GitHub Actions schedule event"
	modeDefault      = "default"
)

// ChooseMode picks the scan's mode: flag (the --mode value, "" when not
// given), else nightly for a GitHub Actions run a schedule started, else
// pr. The mode never comes from a config file: a mode picks which gate
// judges the run, and the scanned repository's creep.yaml must not pick
// the gate that judges it (#28). GitHub sets GITHUB_ACTIONS and
// GITHUB_EVENT_NAME, and refuses a step that writes GITHUB_* to
// $GITHUB_ENV, so a build step cannot turn a pull request into a nightly
// run. Every other CI passes --mode nightly.
func ChooseMode(flag string, getenv func(string) string) (ModeChoice, error) {
	if flag != "" {
		if !slices.Contains(Modes(), flag) {
			return ModeChoice{}, fmt.Errorf("invalid --mode %q: want one of %s", flag, strings.Join(Modes(), ", "))
		}
		return ModeChoice{Mode: Mode(flag), Source: modeFromFlag}, nil
	}
	if getenv("GITHUB_ACTIONS") == "true" && getenv("GITHUB_EVENT_NAME") == "schedule" {
		return ModeChoice{Mode: ModeNightly, Source: modeFromSchedule}, nil
	}
	return ModeChoice{Mode: ModePR, Source: modeDefault}, nil
}

// GateKey is the gates.* key that judges a scan in mode m.
func GateKey(m Mode) string {
	if m == ModeNightly {
		return "gates.nightly"
	}
	return "gates.pr"
}

// Gate returns the gate that judges a scan in mode m and the layer that
// set it. The policy limit of that key already floors it (checkLimits), so
// a limit applies to the mode that reads it.
func (r *Resolved) Gate(m Mode) (value, source string) {
	key := GateKey(m)
	return field(&r.Config, key).String(), r.sources[key]
}

// ExplainMode is what config explain adds after the keys: the mode and
// the gate it reads, with the key and layer that set the gate.
func (r *Resolved) ExplainMode(c ModeChoice) []Entry {
	value, source := r.Gate(c.Mode)
	return []Entry{
		{Key: "mode", Value: string(c.Mode), Source: c.Source},
		{Key: "gate", Value: value, Source: GateKey(c.Mode) + ", " + source},
	}
}

// UnverifiedGate is gateValue read as if no finding could be verified: a
// verified:<severity> gate becomes probable:<severity>; any other gate is
// unchanged. A nightly scan whose verification did not run uses it, so a
// probable finding no PoC tried fails at the gate's severity instead of
// passing unverified. probable is the stricter status, so the result is
// never looser than gateValue.
func UnverifiedGate(gateValue string) (string, error) {
	g, err := parseGate(gateValue)
	if err != nil || g.none || gateStatuses[g.status] == "probable" {
		return gateValue, err
	}
	return "probable:" + gateSeverities[g.severity], nil
}
