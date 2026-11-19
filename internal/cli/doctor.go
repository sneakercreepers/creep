package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/state"
)

// runDoctor checks the configured model, then the sandbox runtime. For a
// command model it runs the tool canary through the gateway (consent,
// budget and egress.log in a new run directory) and exits 3 when the CLI
// has tools. HTTP APIs have no tools to check. The sandbox is optional, so
// a missing runtime is reported, not an error.
func runDoctor(e env, args []string) int {
	if len(args) > 0 {
		printError(e.stderr, "creep doctor", fmt.Errorf("unexpected arguments: %q", args))
		return exitcode.ConfigError
	}
	r, err := loadConfig(e.opts)
	if err == nil {
		err = checkModelConfig(r.Config.Model)
	}
	if err != nil {
		printError(e.stderr, "creep doctor", err)
		return exitcode.ConfigError
	}
	if r.Config.Model.Contract != "command" {
		fmt.Fprintf(e.stdout, "model: %s HTTP contract; an HTTP API runs no tools, so there is no tool canary\n", r.Config.Model.Contract)
		reportSandbox(e, r.Config.Sandbox)
		return exitcode.OK
	}
	return doctorCommand(e, r)
}

// doctorCommand runs the tool canary on the model CLI in a fresh run.
func doctorCommand(e env, r *config.Resolved) int {
	run, closeRun, err := openDoctorRun()
	if err != nil {
		printError(e.stderr, "creep doctor", err)
		return exitcode.ConfigError
	}
	defer closeRun()
	link, err := e.deps.connect(r, run.Dir(), e.stderr)
	if err != nil {
		printError(e.stderr, "creep doctor", err)
		return exitcode.ConfigError
	}
	defer func() { _ = link.close() }()
	if link.command == nil {
		printError(e.stderr, "creep doctor", errors.New("contract command: the model command is not open"))
		return exitcode.ConfigError
	}
	warnPreset(e.stderr, r.Config.Model)
	if err := checkTools(context.Background(), models.NewCanary(), r.Config.Model, link); err != nil {
		printError(e.stderr, "creep doctor: tool canary", err)
		return failureCode(err)
	}
	fmt.Fprintf(e.stdout, "model command %s: tool canary passed (no file was created and no command ran)\n", escapeControl(fmt.Sprintf("%q", link.command.Program())))
	fmt.Fprintf(e.stdout, "consent key for a CI policy: %s\n", link.command.Endpoint())
	reportSandbox(e, r.Config.Sandbox)
	return exitcode.OK
}

func openDoctorRun() (*state.Run, func(), error) {
	store, err := state.OpenUser(stateDir)
	if err != nil {
		return nil, nil, err
	}
	run, err := store.NewRun(state.ModeLive)
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	return run, func() { _ = run.Close(); _ = store.Close() }, nil
}
