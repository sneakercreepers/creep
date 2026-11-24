package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

// initNextSteps tells the user where the settings the project file refuses
// go, since the template cannot hold them (ADR 0031).
const initNextSteps = `creep init: wrote creep.yaml; every setting in it is commented out, so it changes nothing until you edit it.
The model, egress.allow, sandbox, scanners.enabled, report.formats and output.format cannot be set in the project file.
Set them in ~/.creep/config.yaml, a --config file or the policy (CREEP_POLICY), for example:

model:
  preset: claude-code
`

// runInit writes the project file template to ./creep.yaml. It reads no
// config layer and calls no model: the file is data embedded in creep.
func runInit(e env, args []string) int {
	if len(args) > 0 {
		printError(e.stderr, "creep init", fmt.Errorf("unexpected arguments: %q", args))
		return exitcode.ConfigError
	}
	if e.opts.explicit["format"] && e.opts.format != "text" {
		printError(e.stderr, "creep init", fmt.Errorf("prints text only, not --format %q", e.opts.format))
		return exitcode.ConfigError
	}
	if err := writeProjectTemplate(); err != nil {
		printError(e.stderr, "creep init", err)
		return exitcode.ConfigError
	}
	fmt.Fprint(e.stdout, initNextSteps)
	return exitcode.OK
}

// writeProjectTemplate creates creep.yaml exclusively inside the working
// directory's os.Root: an existing file, link, directory or FIFO there is
// never opened, followed or overwritten, and O_EXCL refuses one planted
// between the check and the create.
func writeProjectTemplate() error {
	root, err := os.OpenRoot(".")
	if err != nil {
		return configError("project file", projectFile, err)
	}
	defer root.Close()
	if err := refuseExisting(root); err != nil {
		return err
	}
	return createProjectFile(root)
}

// createProjectFile writes the template to a new creep.yaml in root; a
// failed write removes what it created.
func createProjectFile(root *os.Root) error {
	f, err := root.OpenFile(projectFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return errProjectExists
	}
	if err != nil {
		return configError("project file", projectFile, err)
	}
	_, err = f.Write(config.ProjectTemplate())
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = root.Remove(projectFile)
		return configError("project file", projectFile, err)
	}
	return nil
}

var errProjectExists = fmt.Errorf("project file %q already exists; it was left unchanged", projectFile)

// refuseExisting names what is already at creep.yaml, without following it.
func refuseExisting(root *os.Root) error {
	info, err := recoverStat(root.Lstat)(projectFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return configError("project file", projectFile, err)
	}
	if info.Mode().IsRegular() {
		return errProjectExists
	}
	return fmt.Errorf("project file %q exists and is a link, directory or special file; it was left unchanged", projectFile)
}
