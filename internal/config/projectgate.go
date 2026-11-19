package config

import (
	"fmt"
	"slices"
	"strings"
)

// gateKeys are the gates the project file may only make stricter.
var gateKeys = []string{"gates.pr", "gates.nightly"}

// gateFloor is a gate a project gate must be at least as strict as, and
// the layer that set it.
type gateFloor struct{ value, what, by string }

// applyProject merges the scanned repository's creep.yaml. Forbidden and
// raised keys are refused before the merge; gates are checked after it,
// against the gates the layers before it set (#249).
func (s *state) applyProject(c *Config, keys []string, src string) error {
	if err := s.checkProjectKeys(c, keys, src); err != nil {
		return err
	}
	inherited := s.inheritedGates()
	if err := s.merge(c, keys, src); err != nil {
		return err
	}
	return s.checkProjectGates(keys, src, inherited)
}

// inheritedGates are the gates set by the layers before the project file
// (policy defaults, user file). A gate still at its built-in value adds no
// floor beyond the built-in one, so it is left out.
func (s *state) inheritedGates() map[string]gateFloor {
	floors := map[string]gateFloor{}
	for _, k := range gateKeys {
		if src := s.sources[k]; src != "default" {
			floors[k] = gateFloor{field(&s.Config, k).String(), "the gate", src}
		}
	}
	return floors
}

// checkProjectGates rejects a project gate looser than any of its floors.
// The project file comes from the repository being scanned, so a pull
// request must not loosen the gate that judges it, neither the built-in one
// nor the one the operator set; operator layers (user, --config, flags,
// policy) may still loosen.
func (s *state) checkProjectGates(keys []string, src string, inherited map[string]gateFloor) error {
	for _, k := range keys {
		if !slices.Contains(gateKeys, k) {
			continue
		}
		if err := s.checkProjectGate(k, inherited[k]); err != nil {
			return fmt.Errorf("%s: %w", src, err)
		}
	}
	return nil
}

// checkProjectGate checks one project gate against the policy limit, the
// inherited gate and the built-in default, and names what would pass: the
// strictest broken floor, or, when the broken floors cannot be ordered,
// every one of them and the loosest gate that meets them all.
func (s *state) checkProjectGate(key string, inherited gateFloor) error {
	limits, defaults := Config{Gates: s.limits.Gates}, Defaults()
	floors := []gateFloor{
		{field(&limits, key).String(), "the limit", s.limSrc},
		inherited,
		{field(&defaults, key).String(), "the built-in floor", "default"},
	}
	value := field(&s.Config, key).String()
	var broken []gateFloor
	for _, f := range floors {
		if checkFloor(key, value, f.value, f.what, f.by) != nil {
			broken = append(broken, f)
		}
	}
	if len(broken) == 0 {
		return nil
	}
	f, ok := strictestFloor(broken)
	if !ok {
		return unorderedFloorsError(key, value, broken)
	}
	err := checkFloor(key, value, f.value, f.what, f.by)
	if f.what == "the limit" {
		return err // no layer may loosen past a policy limit
	}
	return fmt.Errorf("%w; the project file may only make gates stricter, set a looser gate in the user file, --config or a flag", err)
}

// strictestFloor returns the first floor at least as strict as all the
// others. Gates are only partly ordered (status and severity), so there may
// be none.
func strictestFloor(floors []gateFloor) (gateFloor, bool) {
	for _, f := range floors {
		if floorCovers(f, floors) {
			return f, true
		}
	}
	return gateFloor{}, false
}

func floorCovers(f gateFloor, floors []gateFloor) bool {
	g, _ := parseGate(f.value) // floors are valid gates, see checkFloor
	for _, other := range floors {
		o, _ := parseGate(other.value)
		if !g.atLeastAsStrict(o) {
			return false
		}
	}
	return true
}

// unorderedFloorsError names every broken floor and the join of them: the
// strictest status and the lowest severity among them, which meets each.
func unorderedFloorsError(key, value string, broken []gateFloor) error {
	var join gate
	names := make([]string, 0, len(broken))
	for _, f := range broken {
		g, _ := parseGate(f.value) // a broken floor is never "none"
		join.status, join.severity = max(join.status, g.status), max(join.severity, g.severity)
		names = append(names, fmt.Sprintf("%s %q set by %s", f.what, f.value, f.by))
	}
	need := gateStatuses[join.status] + ":" + gateSeverities[join.severity]
	return fmt.Errorf("%s %q is looser than %s; the project file may only make gates stricter, use %q or a stricter gate",
		key, value, strings.Join(names, " and "), need)
}
