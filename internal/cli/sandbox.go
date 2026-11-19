package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/sandbox"
)

// sandboxDeps finds the container runtime and removes creep's containers.
// productionDeps sets sandbox.Detect and sandbox.Clean (ADR 0016); a nil
// detect reports the sandbox as not checked, so tests never run a real
// runtime.
type sandboxDeps struct {
	detect func(context.Context, sandbox.Env) sandbox.Report
	clean  func(context.Context, sandbox.Status) (int, error)
}

// detectSandbox checks both runtimes from the current directory, the
// repository during a scan. ok is false when no detector is wired.
func detectSandbox(ctx context.Context, d sandboxDeps, cfg config.Sandbox) (sandbox.Report, bool) {
	if d.detect == nil {
		return sandbox.Report{}, false
	}
	// An unknown directory leaves Repo empty, which refuses every binary.
	repo, _ := os.Getwd()
	env := sandbox.Env{Preferred: sandbox.Runtime(cfg.Runtime), Repo: repo, Getenv: os.Getenv}
	return d.detect(ctx, env), true
}

// reportSandbox is creep doctor's sandbox section: each runtime checked,
// then the one a scan would use with its rootless status and isolation.
func reportSandbox(e env, cfg config.Sandbox) {
	rep, checked := detectSandbox(context.Background(), e.deps.sandbox, cfg)
	if !checked {
		fmt.Fprintln(e.stdout, "sandbox: not checked")
		return
	}
	for _, st := range rep.Checked {
		fmt.Fprintln(e.stdout, describeRuntime(st))
	}
	best, ok := rep.Best()
	if !ok {
		fmt.Fprintln(e.stdout, "sandbox: unavailable: no usable docker or podman; scans still run and findings stay probable")
		return
	}
	fmt.Fprintf(e.stdout, "sandbox: runtime %s, rootless %s, isolation %s\n", best.Runtime, yesNo(best.Rootless), best.Isolation)
	if best.Isolation == sandbox.IsolationRootful {
		fmt.Fprintln(e.stdout, "sandbox: warning: the daemon runs as root, so a container escape gets root on this host; prefer rootless Docker or Podman")
	}
	if !cfg.Enabled {
		fmt.Fprintln(e.stdout, "sandbox: sandbox.enabled is false, so scans do not use it")
	}
	fmt.Fprintln(e.stdout, "sandbox: PoC verification is not built yet (#22); findings stay probable")
}

// describeRuntime is one runtime's line. Runtime, reason and isolation are
// closed IDs; only the path is printed escaped.
func describeRuntime(st sandbox.Status) string {
	if st.Path == "" {
		return fmt.Sprintf("sandbox runtime %s: not usable (%s)", st.Runtime, st.Reason)
	}
	path := escapeControl(fmt.Sprintf("%q", st.Path))
	if !st.Usable() {
		return fmt.Sprintf("sandbox runtime %s %s: not usable (%s)", st.Runtime, path, st.Reason)
	}
	return fmt.Sprintf("sandbox runtime %s %s: usable, rootless %s, isolation %s", st.Runtime, path, yesNo(st.Rootless), st.Isolation)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// noteSandbox tells a scan with sandbox.enabled what verification it gets.
// Without a runtime the scan goes on unchanged: findings stay probable.
func noteSandbox(ctx context.Context, w io.Writer, d sandboxDeps, cfg config.Sandbox) {
	if !cfg.Enabled {
		return
	}
	rep, checked := detectSandbox(ctx, d, cfg)
	best, ok := rep.Best()
	switch {
	case !checked:
		fmt.Fprintln(w, "sandbox: not checked; findings stay probable")
	case !ok:
		fmt.Fprintln(w, "sandbox: unavailable (no usable docker or podman; see creep doctor); verification is off and findings stay probable")
	default:
		fmt.Fprintf(w, "sandbox: %s found (isolation %s); PoC verification is not built yet (#22), so findings stay probable\n", best.Runtime, best.Isolation)
	}
}
