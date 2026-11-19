package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sneakercreepers/creep/internal/static"
)

// Runtime is a container runtime, named as in config sandbox.runtime.
type Runtime string

// The runtimes creep drives.
const (
	Docker Runtime = "docker"
	Podman Runtime = "podman"
)

// Isolation is how far a container escape reaches.
type Isolation string

// Isolation levels, strongest first.
const (
	IsolationRootless Isolation = "rootless" // the runtime runs as the user: an escape gets the user's rights, not root
	IsolationVM       Isolation = "vm"       // the daemon runs in a VM (Docker Desktop): an escape gets root in the VM
	IsolationRootful  Isolation = "rootful"  // the daemon runs as root on this host: an escape gets root here
	IsolationNone     Isolation = "none"     // not usable: nothing runs, findings stay probable
)

// Reason says why a runtime is or is not usable: a closed set of IDs, safe
// to print.
type Reason string

// Reasons.
const (
	ReasonOK             Reason = "ok"
	ReasonNotFound       Reason = "not_found"       // not on PATH
	ReasonRelativePath   Reason = "relative_path"   // found in the current directory or a relative PATH entry
	ReasonInRepository   Reason = "in_repository"   // its final path is in the repository or the working directory
	ReasonNotExe         Reason = "not_exe"         // Windows: a .bat or .cmd would run through cmd.exe
	ReasonRemoteEndpoint Reason = "remote_endpoint" // not a local socket or pipe, or a remote Podman service
	ReasonBadContext     Reason = "bad_context"     // DOCKER_CONTEXT is not a plain context name
	ReasonNotRunning     Reason = "not_running"     // the CLI failed: daemon down, context missing, no permission
	ReasonMalformedInfo  Reason = "malformed_info"  // the runtime's answer did not decode or was too large
	ReasonNotLinux       Reason = "not_linux"       // the daemon runs Windows containers
	ReasonNoSeccomp      Reason = "no_seccomp"      // seccomp is off or unconfined
	ReasonNoLimits       Reason = "no_limits"       // memory, pids or CPU limits cannot be applied
)

// Status is what detection found for one runtime.
type Status struct {
	Runtime   Runtime
	Path      string // final path of the binary; "" unless found
	Host      string // Docker only: the pinned local endpoint passed as --host
	Reachable bool   // local endpoint and the runtime answered; creep clean may use it
	Rootless  bool
	Isolation Isolation // IsolationNone unless Reason is ReasonOK
	Reason    Reason
	env       []string // the CLI's fixed environment
}

// Usable reports a runtime that may start sandbox containers.
func (s Status) Usable() bool { return s.Reason == ReasonOK }

// Env is what detection reads. Repo is the absolute repository root;
// Getenv reads the operator's environment (os.Getenv in production).
type Env struct {
	Preferred Runtime
	Repo      string
	Getenv    func(string) string
}

// Report lists every runtime checked, the preferred one first.
type Report struct {
	Checked []Status
}

// Best is the usable runtime with the strongest isolation; on a tie the
// one checked first (the preferred runtime) wins.
func (r Report) Best() (Status, bool) {
	best, found := Status{}, false
	for _, s := range r.Checked {
		if s.Usable() && (!found || rank(s.Isolation) > rank(best.Isolation)) {
			best, found = s, true
		}
	}
	return best, found
}

func rank(i Isolation) int {
	switch i {
	case IsolationRootless:
		return 3
	case IsolationVM:
		return 2
	case IsolationRootful:
		return 1
	}
	return 0
}

// probeTimeout bounds each runtime's detection.
const probeTimeout = 15 * time.Second

// prober is how detection finds and starts a runtime; tests replace both.
type prober struct {
	look  func(string) (string, error)
	start func(bin string, env []string) runFunc
}

// Detect checks Docker and Podman, the preferred one first. It runs only
// the runtimes' own info commands and never starts a container.
func Detect(ctx context.Context, env Env) Report {
	return detect(ctx, env, prober{look: exec.LookPath, start: newExecRunner})
}

func detect(ctx context.Context, env Env, p prober) Report {
	order := []Runtime{Docker, Podman}
	if env.Preferred == Podman {
		order = []Runtime{Podman, Docker}
	}
	var rep Report
	for _, rt := range order {
		rep.Checked = append(rep.Checked, p.check(ctx, rt, env))
	}
	return rep
}

func (p prober) check(ctx context.Context, rt Runtime, env Env) Status {
	st := Status{Runtime: rt, Isolation: IsolationNone}
	bin, reason := p.locate(string(rt), env.Repo)
	if reason != ReasonOK {
		st.Reason = reason
		return st
	}
	st.Path, st.env = bin, runtimeEnv(env.Getenv, env.Repo)
	run := p.start(bin, st.env)
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if rt == Docker {
		return probeDocker(ctx, run, env.Getenv, st)
	}
	return probePodman(ctx, run, st)
}

// locate finds name on PATH as the OS would. The first match decides, so a
// binary in the current directory or a relative entry is refused rather
// than skipped for a later one (as for scanners, ADR 0013).
func (p prober) locate(name, repo string) (string, Reason) {
	found, err := p.look(name)
	switch {
	case errors.Is(err, exec.ErrDot):
		return "", ReasonRelativePath
	case err != nil:
		return "", ReasonNotFound
	case !filepath.IsAbs(found):
		return "", ReasonRelativePath
	}
	if _, err := os.Stat(found); err != nil {
		return "", ReasonNotFound
	}
	final, ok := static.OutsideRepo(found, repo)
	if !ok {
		return "", ReasonInRepository
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(final), ".exe") {
		return "", ReasonNotExe
	}
	return final, ReasonOK
}
