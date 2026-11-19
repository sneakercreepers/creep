package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
)

// infoLimit caps a runtime's info answer; past it the answer is malformed.
const infoLimit = 1 << 20

// contextName is a plain Docker context name: never a flag, never a path.
var contextName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$`)

// dockerInfo is the part of `docker info` detection reads.
type dockerInfo struct {
	OSType          string
	OperatingSystem string
	SecurityOptions []string
	MemoryLimit     bool
	PidsLimit       bool
	CPUShares       bool
}

// probeDocker pins Docker's endpoint, then reads its info through it.
func probeDocker(ctx context.Context, run runFunc, getenv func(string) string, st Status) Status {
	host, reason := dockerHost(ctx, run, getenv)
	if reason != ReasonOK {
		st.Reason = reason
		return st
	}
	st.Host = host
	res, err := run(ctx, []string{"--host=" + host, "info", "--format", "{{json .}}"}, infoLimit)
	if err != nil || res.exit != 0 {
		st.Reason = ReasonNotRunning
		return st
	}
	var info dockerInfo
	if res.truncated || json.Unmarshal(res.stdout, &info) != nil {
		st.Reason = ReasonMalformedInfo
		return st
	}
	st.Reachable = true
	return classifyDocker(info, st)
}

// dockerHost is the endpoint every Docker call uses: DOCKER_HOST when set,
// else the endpoint of DOCKER_CONTEXT or the current context. Only a unix
// socket or a named pipe is accepted, so the CLI never dials another host.
func dockerHost(ctx context.Context, run runFunc, getenv func(string) string) (string, Reason) {
	if h := getenv("DOCKER_HOST"); h != "" {
		return localHost(h)
	}
	args := []string{"context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"}
	if name := getenv("DOCKER_CONTEXT"); name != "" {
		if !contextName.MatchString(name) {
			return "", ReasonBadContext
		}
		args = append(args, name)
	}
	res, err := run(ctx, args, infoLimit)
	if err != nil || res.exit != 0 {
		return "", ReasonNotRunning
	}
	var host string
	if res.truncated || json.Unmarshal(bytes.TrimSpace(res.stdout), &host) != nil {
		return "", ReasonMalformedInfo
	}
	return localHost(host)
}

// localPipe is a named pipe on this machine. Any other host in a pipe
// path is a UNC path that Windows opens over SMB, sending NTLM.
var localPipe = regexp.MustCompile(`^npipe:////\./pipe/[A-Za-z0-9._-]{1,256}$`)

// localHost accepts a unix socket at an absolute path or a named pipe on
// this machine; anything else could reach another host.
func localHost(h string) (string, Reason) {
	switch {
	case len(h) > 4096 || strings.ContainsAny(h, " \t\r\n\x00"):
		return "", ReasonRemoteEndpoint
	case strings.HasPrefix(h, "unix:///") && len(h) > len("unix:///"):
		return h, ReasonOK
	case localPipe.MatchString(h):
		return h, ReasonOK
	}
	return "", ReasonRemoteEndpoint
}

func classifyDocker(info dockerInfo, st Status) Status {
	st.Rootless = slices.Contains(info.SecurityOptions, "name=rootless")
	switch {
	case info.OSType != "linux":
		st.Reason = ReasonNotLinux
	case !dockerSeccomp(info.SecurityOptions):
		st.Reason = ReasonNoSeccomp
	case !info.MemoryLimit || !info.PidsLimit || !info.CPUShares:
		st.Reason = ReasonNoLimits
	case st.Rootless:
		st.Reason, st.Isolation = ReasonOK, IsolationRootless
	case strings.Contains(info.OperatingSystem, "Docker Desktop"):
		st.Reason, st.Isolation = ReasonOK, IsolationVM
	default:
		st.Reason, st.Isolation = ReasonOK, IsolationRootful
	}
	return st
}

// dockerSeccomp reports a seccomp security option that is not unconfined.
func dockerSeccomp(opts []string) bool {
	for _, o := range opts {
		if strings.HasPrefix(o, "name=seccomp") && !strings.Contains(o, "profile=unconfined") {
			return true
		}
	}
	return false
}

// podmanInfo is the part of `podman info` detection reads.
type podmanInfo struct {
	Host struct {
		OS                string   `json:"os"`
		ServiceIsRemote   bool     `json:"serviceIsRemote"`
		CgroupControllers []string `json:"cgroupControllers"`
		Security          struct {
			Rootless       bool `json:"rootless"`
			SeccompEnabled bool `json:"seccompEnabled"`
		} `json:"security"`
	} `json:"host"`
}

// podmanRemoteEnv are the variables that turn Podman into a client of a
// service elsewhere. creep never passes them, and an operator who set them
// wants a remote Podman, which creep refuses without starting it.
var podmanRemoteEnv = []string{"CONTAINER_HOST", "CONTAINER_CONNECTION"}

// podmanLocal reports whether Podman can run here without a remote
// service: only on Linux (elsewhere the CLI is always a client of a podman
// machine) and with no remote variable set. It runs nothing.
func podmanLocal(goos string, getenv func(string) string) bool {
	if goos != "linux" {
		return false
	}
	for _, name := range podmanRemoteEnv {
		if getenv(name) != "" {
			return false
		}
	}
	return true
}

// probePodman reads Podman's info with --remote=false (globalArgs), so a
// containers.conf that makes Podman a client is overridden; a service that
// still reports itself remote is refused: creep drives only a local Podman.
func probePodman(ctx context.Context, run runFunc, st Status) Status {
	res, err := run(ctx, append(globalArgs(st), "info", "--format", "json"), infoLimit)
	if err != nil || res.exit != 0 {
		st.Reason = ReasonNotRunning
		return st
	}
	var info podmanInfo
	if res.truncated || json.Unmarshal(res.stdout, &info) != nil {
		st.Reason = ReasonMalformedInfo
		return st
	}
	if info.Host.ServiceIsRemote {
		st.Reason = ReasonRemoteEndpoint
		return st
	}
	st.Reachable = true
	return classifyPodman(info, st)
}

func classifyPodman(info podmanInfo, st Status) Status {
	st.Rootless = info.Host.Security.Rootless
	ctl := info.Host.CgroupControllers
	switch {
	case info.Host.OS != "linux":
		st.Reason = ReasonNotLinux
	case !info.Host.Security.SeccompEnabled:
		st.Reason = ReasonNoSeccomp
	case !slices.Contains(ctl, "memory") || !slices.Contains(ctl, "pids") || !slices.Contains(ctl, "cpu"):
		st.Reason = ReasonNoLimits
	case st.Rootless:
		st.Reason, st.Isolation = ReasonOK, IsolationRootless
	default:
		st.Reason, st.Isolation = ReasonOK, IsolationRootful
	}
	return st
}
