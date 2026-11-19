package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/sandbox"
)

// runClean removes every container creep labeled on each local runtime it
// can reach: what a killed or crashed run left behind (ADR 0016). A
// runtime that is missing or not running holds nothing to remove; one that
// answers but fails to remove makes clean exit 3.
func runClean(e env, args []string) int {
	if len(args) > 0 {
		printError(e.stderr, "creep clean", fmt.Errorf("unexpected arguments: %q", args))
		return exitcode.ConfigError
	}
	r, err := loadConfig(e.opts)
	if err != nil {
		printError(e.stderr, "creep clean", err)
		return exitcode.ConfigError
	}
	if e.deps.sandbox.clean == nil {
		printError(e.stderr, "creep clean", errors.New("no container runtime driver"))
		return exitcode.ModelOrSandbox
	}
	ctx := context.Background()
	rep, checked := detectSandbox(ctx, e.deps.sandbox, r.Config.Sandbox)
	if !checked {
		printError(e.stderr, "creep clean", errors.New("no container runtime probe"))
		return exitcode.ModelOrSandbox
	}
	code := exitcode.OK
	for _, st := range rep.Checked {
		if !cleanRuntime(ctx, e, st) {
			code = exitcode.ModelOrSandbox
		}
	}
	return code
}

func cleanRuntime(ctx context.Context, e env, st sandbox.Status) bool {
	if !st.Reachable {
		fmt.Fprintf(e.stdout, "%s: not reachable (%s); nothing removed\n", st.Runtime, st.Reason)
		return true
	}
	n, err := e.deps.sandbox.clean(ctx, st)
	if err != nil {
		printError(e.stderr, "creep clean: "+string(st.Runtime), err)
		return false
	}
	fmt.Fprintf(e.stdout, "%s: removed %d creep container(s)\n", st.Runtime, n)
	return true
}
