package sandbox

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Mirror is the operator's build mirror (ADR 0029): an internal network
// the operator created, with its own mirror or allowlisting proxy on it,
// and the proxy URL that build steps get. creep opens no connection to
// either: the build's RUN steps do, inside the builder. The zero Mirror
// keeps the build offline, the default.
type Mirror struct {
	Bridge string // name of the operator's internal network; "" keeps the build offline
	Proxy  string // http(s)://host[:port] given to RUN steps as HTTP(S)_PROXY; optional
}

// Set reports whether the operator configured a mirror at all.
func (m Mirror) Set() bool { return m.Bridge != "" || m.Proxy != "" }

// bridgeName is a network name both runtimes accept and no flag can be
// read from. reservedBridges are the network modes `--network` would read
// instead of a network: host would give RUN steps the host's network.
var (
	bridgeName      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	proxyURL        = regexp.MustCompile(`^https?://[A-Za-z0-9]([A-Za-z0-9.-]{0,252})(:[0-9]{1,5})?/?$`)
	reservedBridges = []string{"none", "host", "bridge", "default", "private", "slirp4netns", "pasta", "podman", "container", "ns"}
)

// proxyBuildArgs are the build arguments the proxy is given as. Both
// builders pass them to RUN steps without an ARG in the Dockerfile and
// keep them out of the image's history.
var proxyBuildArgs = []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"}

// Mirror refusal details, each an ID for the report.
const (
	mirrorBuilder     = "builder"      // Docker's BuildKit cannot run a build on a user-defined network
	mirrorRootful     = "rootful"      // rootful Podman's bridge has an address on the host
	mirrorConfig      = "config"       // the bridge name or proxy URL is malformed, or a proxy has no bridge
	mirrorMissing     = "missing"      // the network does not exist or inspect failed
	mirrorNotInternal = "not_internal" // the network is not an internal IPv4 bridge
	mirrorLeak        = "leak"         // the canary reached a public address or name from the network
	mirrorCanary      = "canary"       // the canary was inconclusive
)

// UseMirror makes later builds run on the operator's mirror network
// instead of none. Build checks it before each build and refuses the
// build (BuildMirrorRefused), never the scan, when it does not hold.
func (s *Sandbox) UseMirror(m Mirror) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mirror = m
}

func (s *Sandbox) currentMirror() Mirror {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mirror
}

// Valid reports whether creep would pass m to a builder: a bridge name
// that is no network mode or flag, and a proxy with only a scheme, host
// and port. internal/config checks the same rules when it loads the
// setting; cli.TestMirrorRulesMatchConfig keeps the two in step.
func (m Mirror) Valid() bool {
	if !bridgeName.MatchString(m.Bridge) || slices.Contains(reservedBridges, strings.ToLower(m.Bridge)) {
		return false
	}
	return m.Proxy == "" || proxyURL.MatchString(m.Proxy)
}

// clearMirror checks the operator's network before a build: only rootless
// Podman, a well-formed setting, an internal IPv4 bridge, and a canary on
// it that reaches itself and nothing public. Any failure refuses the
// build; only the caller's cancel returns an error.
func (s *Sandbox) clearMirror(ctx context.Context, m Mirror) (*refusal, error) {
	switch {
	case !m.Valid():
		return refuse(BuildMirrorRefused, mirrorConfig), nil
	case s.status.Runtime != Podman:
		return refuse(BuildMirrorRefused, mirrorBuilder), nil
	case !s.status.Rootless:
		return refuse(BuildMirrorRefused, mirrorRootful), nil
	}
	if why, err := s.inspectBridge(ctx, m.Bridge); why != nil || err != nil {
		return why, err
	}
	err := s.canaryOn(ctx, m.Bridge)
	switch {
	case err == nil:
		return nil, nil
	case ctx.Err() != nil:
		return nil, fmt.Errorf("sandbox build: %w", ctx.Err())
	case errors.Is(err, ErrNetworkLeak):
		return refuse(BuildMirrorRefused, mirrorLeak), nil
	}
	return refuse(BuildMirrorRefused, mirrorCanary), nil
}

// inspectBridge reads the network's driver, internal flag and IPv6 flag in
// a fixed format: it must be an internal bridge without IPv6, the address
// family the canary does not test.
func (s *Sandbox) inspectBridge(ctx context.Context, bridge string) (*refusal, error) {
	inspectCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	args := append(s.global(), "network", "inspect", "--format", "{{.Driver}}/{{.Internal}}/{{.IPv6Enabled}}", bridge)
	res, err := s.run(inspectCtx, args, infoLimit)
	switch {
	case ctx.Err() != nil:
		return nil, fmt.Errorf("sandbox build: %w", ctx.Err())
	case err != nil || res.exit != 0 || res.truncated:
		return refuse(BuildMirrorRefused, mirrorMissing), nil
	case strings.TrimSpace(string(res.stdout)) != "bridge/true/false":
		return refuse(BuildMirrorRefused, mirrorNotInternal), nil
	}
	return nil, nil
}

// mirrorArgs are the options a mirror adds to a Podman build line: the
// operator's network in place of none, and the proxy as build arguments.
// Docker never gets them (clearMirror refuses it first, and buildArgs
// ignores the mirror for Docker).
func mirrorArgs(m Mirror) (network string, extra []string) {
	if m.Bridge == "" {
		return "none", nil
	}
	if m.Proxy != "" {
		for _, name := range proxyBuildArgs {
			extra = append(extra, "--build-arg="+name+"="+m.Proxy)
		}
	}
	return m.Bridge, extra
}
