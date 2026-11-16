package config

import (
	"fmt"
	"slices"
	"strings"
)

// gateNone disables a gate: no finding ever fails the run.
const gateNone = "none"

// A gate "<status>:<severity>" fails the run on findings with at least that
// status and severity. probable includes verified findings, so it is the
// stricter status; a lower severity is a stricter threshold.
var (
	gateStatuses   = []string{"verified", "probable"} // loosest first
	gateSeverities = []string{"critical", "high", "medium", "low", "info"}
)

type gate struct {
	none     bool
	status   int // index in gateStatuses; higher is stricter
	severity int // index in gateSeverities; higher is stricter
}

func parseGate(s string) (gate, error) {
	if s == gateNone {
		return gate{none: true}, nil
	}
	status, severity, ok := strings.Cut(s, ":")
	st := slices.Index(gateStatuses, status)
	sv := slices.Index(gateSeverities, severity)
	if !ok || st < 0 || sv < 0 {
		return gate{}, fmt.Errorf("invalid gate %q: want <status>:<severity> with status in %s and severity in %s, or %q",
			s, strings.Join(gateStatuses, ", "), strings.Join(gateSeverities, ", "), gateNone)
	}
	return gate{status: st, severity: sv}, nil
}

// GateTrips reports whether a finding with status and severity fails gate
// (a gates.* value). Statuses other than verified and probable (discarded,
// not evaluated) never trip a gate; an invalid gate or severity is an error.
func GateTrips(gateValue, status, severity string) (bool, error) {
	g, err := parseGate(gateValue)
	if err != nil {
		return false, err
	}
	sv := slices.Index(gateSeverities, severity)
	if sv < 0 {
		return false, fmt.Errorf("invalid severity %q: want one of %s", severity, strings.Join(gateSeverities, ", "))
	}
	st := slices.Index(gateStatuses, status)
	if g.none || st < 0 {
		return false, nil
	}
	// Lower indexes are stronger statuses and higher severities.
	return st <= g.status && sv <= g.severity, nil
}

// atLeastAsStrict reports whether g fails on every finding limit fails on.
func (g gate) atLeastAsStrict(limit gate) bool {
	if limit.none {
		return true
	}
	if g.none {
		return false
	}
	return g.status >= limit.status && g.severity >= limit.severity
}

// gatePattern is the JSON Schema pattern for gate keys.
func gatePattern() string {
	return fmt.Sprintf("^(%s|(%s):(%s))$", gateNone,
		strings.Join(gateStatuses, "|"), strings.Join(gateSeverities, "|"))
}
