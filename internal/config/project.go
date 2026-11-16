package config

import (
	"fmt"
	"slices"
)

// checkProjectKeys applies the project file's restrictions before its keys
// merge: the scanned repository may tighten what the operator set, never
// loosen it. Gates are checked after the merge (checkProjectGates).
func (s *state) checkProjectKeys(c *Config, keys []string, src string) error {
	for _, k := range keys {
		if err := s.checkProjectKey(c, k, src); err != nil {
			return err
		}
	}
	return nil
}

func (s *state) checkProjectKey(c *Config, k, src string) error {
	switch {
	case projectForbidden[k]:
		return fmt.Errorf("%s: key %q cannot be set in the project file, because the scanned repository must not choose where its code is sent, which model reads it or how it is run; set it in the user file, --config or policy", src, k)
	case k == "scanners.enabled":
		return s.checkProjectScanners(c.Scanners.Enabled, src)
	case slices.Contains(projectLowerOnly, k):
		return s.checkProjectCeiling(c, k, src)
	}
	return nil
}

// checkProjectScanners rejects a project file that enables a scanner the
// layers before it did not: enabling one runs a program on the host
// (ADR 0013), which the scanned repository must not choose. It may only
// remove scanners.
func (s *state) checkProjectScanners(project []string, src string) error {
	for _, name := range project {
		if !slices.Contains(s.Config.Scanners.Enabled, name) {
			return fmt.Errorf("%s: key \"scanners.enabled\" cannot enable %q in the project file, because the scanned repository must not choose which programs run on this machine; the project file may only remove scanners, enable it in the user file, --config or policy", src, name)
		}
	}
	return nil
}

// checkProjectCeiling rejects a project value above the one the layers
// before it set (the built-in default when none did): the scanned
// repository must not spend the operator's budget, hold a model command for
// longer, or keep a stale calibration.
func (s *state) checkProjectCeiling(c *Config, k, src string) error {
	inherited, value := field(&s.Config, k).Int(), field(c, k).Int()
	if value <= inherited {
		return nil
	}
	return fmt.Errorf("%s: key %q cannot raise %d to %d in the project file, because the scanned repository must not raise the operator's limits; the project file may only lower it, set a higher value in the user file, --config or policy (set by %s)", src, k, inherited, value, s.sources[k])
}
