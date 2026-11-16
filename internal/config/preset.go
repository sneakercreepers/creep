package config

import (
	"fmt"

	"github.com/sneakercreepers/creep/internal/presets"
)

// checkPreset accepts no preset or the name of an embedded one. Presets
// are never read from disk, so a name cannot point at a file.
func checkPreset(name string) error {
	if name == "" {
		return nil
	}
	_, err := presets.Lookup(name)
	return err
}

// applyPreset turns model.preset into model.run and contract command after
// every layer has applied. The preset's source is recorded on both keys, so
// `config explain` shows where the command came from. A preset never
// overrides a command line or contract that a layer set on purpose: two
// sources for the model command is an error, not a silent choice.
func (s *state) applyPreset() error {
	name := s.Config.Model.Preset
	if name == "" {
		return nil
	}
	src := s.sources["model.preset"]
	p, err := presets.Lookup(name)
	if err != nil {
		return fmt.Errorf("%s: model.preset: %w", src, err)
	}
	if err := s.checkPresetConflicts(p, src); err != nil {
		return err
	}
	run, err := p.CommandLine(s.Config.Model.Name)
	if err != nil {
		return fmt.Errorf("%s: model.preset: %w", src, err)
	}
	if err := checkCommandLine(run); err != nil {
		return fmt.Errorf("%s: model.preset %q: %w", src, name, err)
	}
	s.Config.Model.Run, s.Config.Model.Contract = run, "command"
	from := fmt.Sprintf("preset %q via %s", name, src)
	s.sources["model.run"] = from
	if _, locked := s.locked["model.contract"]; !locked {
		s.sources["model.contract"] = from
	}
	return nil
}

// checkPresetLocks keeps a policy lock binding when a preset would write the
// locked key: a lock pins the value even when it is the default, so a preset
// may not set model.run under any lock, nor change a locked contract.
func (s *state) checkPresetLocks(p presets.Preset, src string) error {
	if pol, ok := s.locked["model.run"]; ok {
		return fmt.Errorf("%s: model.preset %q would set model.run, which is locked by %s", src, p.Name, pol)
	}
	if pol, ok := s.locked["model.contract"]; ok && s.Config.Model.Contract != "command" {
		return fmt.Errorf("%s: model.preset %q would set model.contract to command, but it is locked to %q by %s", src, p.Name, s.Config.Model.Contract, pol)
	}
	return nil
}

// checkPresetConflicts refuses a preset next to another model command or a
// non-command contract. model.name cannot come from the project file at all
// (projectForbidden), so the name a preset passes on is the operator's.
func (s *state) checkPresetConflicts(p presets.Preset, src string) error {
	if err := s.checkPresetLocks(p, src); err != nil {
		return err
	}
	if runSrc := s.sources["model.run"]; runSrc != "default" {
		return fmt.Errorf("%s: model.preset %q and model.run (set by %s) both choose the model command; keep one", src, p.Name, runSrc)
	}
	if c := s.Config.Model.Contract; c != "command" && s.sources["model.contract"] != "default" {
		return fmt.Errorf("%s: model.preset %q needs contract command, but model.contract is %q (set by %s)", src, p.Name, c, s.sources["model.contract"])
	}
	return nil
}
