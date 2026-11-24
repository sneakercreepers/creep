package config

import (
	_ "embed" // the project file template is data in project_template.yaml
	"slices"
)

//go:embed project_template.yaml
var projectTemplate []byte

// ProjectTemplate is the creep.yaml `creep init` writes (ADR 0031): only
// keys the project layer accepts, each commented out at its built-in
// default, so the file changes no effective value until it is edited
// (TestProjectTemplate). Changes to it are additive only.
func ProjectTemplate() []byte { return slices.Clone(projectTemplate) }
