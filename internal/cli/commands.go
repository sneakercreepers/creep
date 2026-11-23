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
	{"accept", "accept <id> --expires 90d --reason \"...\": record a finding of the last scan as an accepted risk in the baseline file", runAccept},
	{"reproduce", "reproduce <id>: run a verified finding's PoC again from its bundle, in the sandbox, without a model", runReproduce},
	{"clean", "remove the containers, app images and networks creep left on local docker or podman, from any run", runClean},
	{"resume", "resume <run>: continue an interrupted run (checks the run; continuing it is not implemented yet)", runResume},
	{"version", "print version, commit and Go version", runVersion},
	{"config", "explain: show each effective config value and the layer it came from", runConfig},
	{"bench", "run creep-bench: the embedded corpus and its safe twins at tiers S, M and L, scored for recall, false positives and honesty per class; --replay reproduces the published numbers with no network (ADR 0030)", runBench},
	{"recipe", "new|lint|test <file.json>: write a recipe template, check a recipe, or load it by running its fixtures through the reader with your model (ADR 0025); add github.com/<owner>/<repo>@<commit> <clone>: install a source's recipes from your clone at that commit, pinned in creep.lock (ADR 0028)", runRecipe},
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
