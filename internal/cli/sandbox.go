package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/sandbox"
)

// sandboxDeps finds the container runtime, builds the app and removes
// creep's containers. productionDeps sets sandbox.Detect, sandbox.Clean,
// sandbox.Images and openSandbox (ADR 0016); a nil detect or open reports
// the sandbox as not checked, so tests never run a real runtime.
type sandboxDeps struct {
	detect func(context.Context, sandbox.Env) sandbox.Report
	clean  func(context.Context, sandbox.Status) (sandbox.Removed, error)
	images func(context.Context, sandbox.Status) []sandbox.PinnedImage
	open   func(st sandbox.Status, runID string) (appSandbox, error)
	// interrupt and now default to Ctrl+C and time.Now; tests replace them.
	interrupt func(context.Context) (context.Context, context.CancelFunc)
	now       func() time.Time
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
	reportImages(e, best)
	fmt.Fprintln(e.stdout, "sandbox: with sandbox.enabled, a scan builds the app offline and runs a PoC 5 times for each probable sqli, path_traversal or template_injection finding; only a PoC that verified makes a finding verified")
}

// reportImages lists the digest-pinned images the run network needs
// (canary, database). creep never pulls, so a missing one comes with the
// command that pulls exactly that digest.
func reportImages(e env, best sandbox.Status) {
	if e.deps.sandbox.images == nil {
		return
	}
	for _, img := range e.deps.sandbox.images(context.Background(), best) {
		if img.Present {
			fmt.Fprintf(e.stdout, "sandbox image %s %s: present\n", img.Role, img.Ref)
			continue
		}
		pull := escapeControl(strings.Join(sandbox.PullArgs(best, img.Ref), " "))
		fmt.Fprintf(e.stdout, "sandbox image %s %s: missing; creep never pulls, run: %s %s\n", img.Role, img.Ref, best.Runtime, pull)
	}
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
