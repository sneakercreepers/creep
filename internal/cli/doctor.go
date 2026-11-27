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

// runDoctor checks the configured model, then the sandbox runtime. Every
// model call goes through the gateway of a new run directory (consent,
// budget, egress.log): for a command model the tool canary first, which
// exits 3 when the CLI has tools, then, for every contract, the model
// probes of doctorModel (ADR 0034). The sandbox is optional, so a missing
// runtime is reported, not an error.
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
	if code := doctorRun(e, r); code != exitcode.OK {
		return code
	}
	reportSandbox(e, r.Config.Sandbox)
	return exitcode.OK
}

// doctorRun checks the model in a fresh run.
func doctorRun(e env, r *config.Resolved) int {
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
	ctx := context.Background()
	if r.Config.Model.Contract == "command" {
		if code := doctorCommand(ctx, e, r, link); code != exitcode.OK {
			return code
		}
	} else {
		fmt.Fprintf(e.stdout, "model: %s HTTP contract; an HTTP API runs no tools, so there is no tool canary\n", r.Config.Model.Contract)
	}
	if err := doctorModel(ctx, e, r, link); err != nil {
		printError(e.stderr, "creep doctor: model probe", err)
		return failureCode(err)
	}
	return exitcode.OK
}

// doctorCommand runs the tool canary on the model CLI.
func doctorCommand(ctx context.Context, e env, r *config.Resolved, link modelLink) int {
	if link.command == nil {
		printError(e.stderr, "creep doctor", errors.New("contract command: the model command is not open"))
		return exitcode.ConfigError
	}
	warnPreset(e.stderr, r.Config.Model)
	if err := checkTools(ctx, models.NewCanary(), r.Config.Model, link); err != nil {
		printError(e.stderr, "creep doctor: tool canary", err)
		return failureCode(err)
	}
	fmt.Fprintf(e.stdout, "model command %s: tool canary passed (no file was created and no command ran)\n", escapeControl(fmt.Sprintf("%q", link.command.Program())))
	fmt.Fprintf(e.stdout, "consent key for a CI policy: %s\n", link.command.Endpoint())
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
