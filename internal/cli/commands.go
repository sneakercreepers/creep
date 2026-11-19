package cli

import (
	"fmt"
	"io"

	"github.com/sneakercreepers/creep/internal/buildinfo"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

// env is what a command needs from Run.
type env struct {
	stdout io.Writer
	stderr io.Writer
	opts   globalOptions
	deps   scanDeps
}

type command struct {
	name    string
	summary string
	run     func(e env, args []string) int
}

var commands = []command{
	{"init", "create a creep.yaml for this project (not implemented yet)", stub("init")},
	{"doctor", "check the model (a command model must pass the tool canary) and the sandbox runtime", runDoctor},
	{"scan", "scan the repository in the current directory; reports go to .creep/", runScan},
	{"estimate", "estimate the calls, tokens, time and cost of a scan here, without calling a model", runEstimate},
	{"why", "why <id>: show the evidence behind a finding of the last scan", runWhy},
	{"clean", "remove the containers creep left on local docker or podman, from any run", runClean},
	{"resume", "resume <run>: continue an interrupted run (checks the run; continuing it is not implemented yet)", runResume},
	{"version", "print version, commit and Go version", runVersion},
	{"config", "explain: show each effective config value and the layer it came from", runConfig},
}

func findCommand(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// stub keeps a contracted command registered but fails closed: a CI gate
// running an unbuilt "creep scan" must not pass with nothing scanned.
func stub(name string) func(env, []string) int {
	return func(e env, _ []string) int {
		fmt.Fprintf(e.stderr, "creep %s: not implemented yet\n", name)
		return exitcode.ConfigError
	}
}

func runVersion(e env, args []string) int {
	if len(args) > 0 {
		fmt.Fprintf(e.stderr, "creep version: unexpected arguments: %q\n", args)
		return exitcode.ConfigError
	}
	info := buildinfo.Get()
	fmt.Fprintf(e.stdout, "creep %s\ncommit: %s\ngo: %s\n", info.Version, info.Commit, info.GoVersion)
	return exitcode.OK
}
