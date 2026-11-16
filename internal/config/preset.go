package config

import (
	"fmt"
	"strings"

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
	s.sources["model.run"], s.sources["model.contract"] = from, from
	return nil
}

// checkPresetConflicts refuses a preset next to another model command, a
// non-command contract, or a model name from the scanned repository when
// that name becomes an argument of the CLI.
func (s *state) checkPresetConflicts(p presets.Preset, src string) error {
	if runSrc := s.sources["model.run"]; runSrc != "default" {
		return fmt.Errorf("%s: model.preset %q and model.run (set by %s) both choose the model command; keep one", src, p.Name, runSrc)
	}
	if c := s.Config.Model.Contract; c != "command" && s.sources["model.contract"] != "default" {
		return fmt.Errorf("%s: model.preset %q needs contract command, but model.contract is %q (set by %s)", src, p.Name, c, s.sources["model.contract"])
	}
	if p.NeedsModel() && strings.HasPrefix(s.sources["model.name"], "project ") {
		return fmt.Errorf("%s: model.name: preset %q passes it to the CLI, so it cannot come from the project file (the scanned repository must not choose what the CLI runs or downloads); set it in the user file, --config or policy", s.sources["model.name"], p.Name)
	}
	return nil
}
