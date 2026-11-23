package sandbox

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The hardened profile. Fixed, not configurable: a looser value would be a
// weaker sandbox, and nothing in a scanned repository may choose it.
const (
	containerUser = "65534:65534" // nobody: never root inside the container
	pidsLimit     = "128"
	memoryLimit   = "512m" // memory and memory+swap alike: no swap
	cpuLimit      = "1"
	tmpfsMount    = "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"
	// serviceTmpfs backs a service's writable directories (a database's
	// data): in memory, counted against the memory limit, never on the host.
	serviceTmpfs = "rw,noexec,nosuid,nodev,size=256m,mode=1777"
)

// Per-container timeouts.
const (
	DefaultTimeout = time.Minute
	MaxTimeout     = 10 * time.Minute
)

// Bounds on a Spec.
const (
	maxArgs     = 64
	maxEnv      = 64
	maxMounts   = 16
	maxValueLen = 4096
	maxTmpfs    = 4
	outputLimit = 1 << 20 // container stdout kept per run
)

// ErrSpec marks a Spec the profile refuses.
var ErrSpec = errors.New("sandbox spec refused")

// Mount is a read-only bind mount of one regular file creep wrote in the
// sandbox's work directory (WriteSyntheticEnv) to an absolute path inside
// the container.
type Mount struct {
	Source string
	Target string
}

// Spec is one container to run. Image must be digest-pinned
// (name@sha256:<hex> or sha256:<hex>) and already present: runs never pull.
// Env holds only synthetic values; a name without a value would copy the
// host's, so there is no way to say that.
type Spec struct {
	Image   string
	Cmd     []string
	Env     map[string]string
	Mounts  []Mount
	Timeout time.Duration // 0 is DefaultTimeout

	// Set only inside this package, so no caller can put a container on
	// the run's network before the canary passed (RunBatch, StartDatabase)
	// or keep one running past its timeout.
	networked bool     // the run's internal network instead of none
	bridge    string   // with networked: the operator's mirror network instead (the build canary only)
	alias     string   // the container's name on that network
	detach    bool     // a service: runs until Close
	tmpfs     []string // extra tmpfs targets; each may cover an image VOLUME
	workdir   string   // the app's checked working directory; "" keeps the image's
}

var (
	pinnedImage = regexp.MustCompile(`^([a-z0-9][a-z0-9._/:-]{0,254}@)?sha256:[0-9a-f]{64}$`)
	envName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	aliasName   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

// proxyVars are the proxy variables a runtime copies into containers on
// its own: Docker from the proxies in the operator's config.json (with any
// credentials in the URL), Podman from its environment. Each is set empty
// in every container, and a spec may not set one.
var proxyVars = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "NO_PROXY", "ALL_PROXY",
	"http_proxy", "https_proxy", "ftp_proxy", "no_proxy", "all_proxy",
}

// hardenedFlags are the run options every container gets, in order;
// network is "none" or the run's internal network.
// --log-driver=none: the attached CLI still gets stdout (capped), but the
// runtime keeps no log file of its own, which no limit would bound.
func hardenedFlags(rt Runtime, network string) []string {
	flags := []string{
		"--rm", "--pull=never", "--network=" + network,
		"--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--read-only", "--tmpfs=" + tmpfsMount, "--user=" + containerUser,
		"--pids-limit=" + pidsLimit, "--memory=" + memoryLimit, "--memory-swap=" + memoryLimit,
		"--cpus=" + cpuLimit, "--ipc=private", "--log-driver=none",
	}
	if rt == Podman {
		flags = append(flags, "--http-proxy=false")
	}
	for _, name := range proxyVars {
		flags = append(flags, "--env="+name+"=")
	}
	return flags
}

// runArgs is the only builder of a `run` command line: the global flags,
// the hardened profile, the network, creep's labels, the spec's checked
// env and mounts, then the image and its command, which the runtime never
// reads as flags. No option that publishes a port is ever built.
func (s *Sandbox) runArgs(name string, spec Spec) ([]string, error) {
	if err := checkSpec(spec); err != nil {
		return nil, err
	}
	mounts, err := s.mountArgs(spec.Mounts)
	if err != nil {
		return nil, err
	}
	network, err := s.networkFor(spec)
	if err != nil {
		return nil, err
	}
	args := append(s.global(), "run", "--name="+name)
	if spec.detach {
		args = append(args, "--detach")
	}
	args = append(args, hardenedFlags(s.status.Runtime, network)...)
	if spec.alias != "" {
		args = append(args, "--network-alias="+spec.alias)
	}
	if spec.workdir != "" {
		args = append(args, "--workdir="+spec.workdir)
	}
	for _, t := range spec.tmpfs {
		args = append(args, "--tmpfs="+t+":"+serviceTmpfs)
	}
	args = append(args, "--label="+LabelManaged+"=true", "--label="+LabelRun+"="+s.runID, "--label="+LabelContainer+"="+name)
	args = append(args, envArgs(spec.Env)...)
	args = append(args, mounts...)
	args = append(args, spec.Image)
	return append(args, spec.Cmd...), nil
}

func checkSpec(spec Spec) error {
	switch {
	case !pinnedImage.MatchString(spec.Image):
		return fmt.Errorf("image %q is not pinned by digest: %w", spec.Image, ErrSpec)
	case len(spec.Cmd) > maxArgs || len(spec.Env) > maxEnv || len(spec.Mounts) > maxMounts:
		return fmt.Errorf("too many arguments, variables or mounts: %w", ErrSpec)
	case spec.Timeout < 0 || spec.Timeout > MaxTimeout:
		return fmt.Errorf("timeout %s outside 0..%s: %w", spec.Timeout, MaxTimeout, ErrSpec)
	case spec.bridge != "" && (!spec.networked || !checkMirrorConfig(Mirror{Bridge: spec.bridge})):
		return fmt.Errorf("network %q: %w", spec.bridge, ErrSpec)
	case spec.alias != "" && (!spec.networked || !aliasName.MatchString(spec.alias)):
		return fmt.Errorf("network alias %q: %w", spec.alias, ErrSpec)
	case spec.workdir != "" && checkContainerPath(spec.workdir) != "":
		return fmt.Errorf("working directory %q: %w", spec.workdir, ErrSpec)
	case len(spec.tmpfs) > maxTmpfs:
		return fmt.Errorf("too many tmpfs mounts: %w", ErrSpec)
	}
	for _, t := range spec.tmpfs {
		if checkTarget(t) != nil || strings.Contains(t, ":") {
			return fmt.Errorf("tmpfs %q: %w", t, ErrSpec)
		}
	}
	for _, a := range spec.Cmd {
		if !plainValue(a) {
			return fmt.Errorf("command argument: %w", ErrSpec)
		}
	}
	for name, v := range spec.Env {
		if !envName.MatchString(name) || !plainValue(v) || isProxyVar(name) {
			return fmt.Errorf("env %q: %w", name, ErrSpec)
		}
	}
	return nil
}

// isProxyVar matches proxy names in any case: Go and curl read both forms.
func isProxyVar(name string) bool {
	for _, p := range proxyVars {
		if strings.EqualFold(p, name) {
			return true
		}
	}
	return false
}

// plainValue refuses NUL and line breaks, which no argument or variable
// needs and which could split an --env value.
func plainValue(v string) bool {
	return len(v) <= maxValueLen && !strings.ContainsAny(v, "\x00\r\n")
}

func envArgs(env map[string]string) []string {
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	slices.Sort(names)
	args := make([]string, 0, len(names))
	for _, name := range names {
		args = append(args, "--env="+name+"="+env[name])
	}
	return args
}

func timeoutOf(spec Spec) time.Duration {
	if spec.Timeout == 0 {
		return DefaultTimeout
	}
	return spec.Timeout
}
