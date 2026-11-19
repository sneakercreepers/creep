package sandbox

import (
	"context"
	"errors"
	"fmt"
)

// ErrHostReachable refuses an internal network on rootful Podman: its
// bridge keeps a gateway address in the host's namespace (aardvark-dns
// listens there), so any local process could reach the services on it.
var ErrHostReachable = errors.New("sandbox network would be reachable from the host")

// networkArgs is the only builder of a `network create` command line:
//   - --internal: no route out of the network, so no internet;
//   - Docker's inhibit_ipv4: the bridge gets no address on the host, so
//     nothing on the host can reach a container (an internal network
//     still has one otherwise, and on a rootful daemon the host can then
//     connect to every container on it);
//   - --ipv6=false: no second address family the canary does not test,
//     whatever the daemon's default network options say.
//
// No port is ever published: run builds no --publish option.
func networkArgs(st Status, name, runID string) []string {
	args := append(globalArgs(st), "network", "create", "--driver=bridge", "--internal", "--ipv6=false")
	if st.Runtime == Docker {
		args = append(args, "--opt=com.docker.network.bridge.inhibit_ipv4=true")
	}
	return append(args, "--label="+LabelManaged+"=true", "--label="+LabelRun+"="+runID, name)
}

// ensureNetwork creates the run's network, creep-<run>, once.
func (s *Sandbox) ensureNetwork(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.network != "" {
		return nil
	}
	if s.status.Runtime == Podman && !s.status.Rootless {
		return fmt.Errorf("create network: %w", ErrHostReachable)
	}
	name := "creep-" + s.runID
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	res, err := s.run(ctx, s.netArgs(s.status, name, s.runID), infoLimit)
	if err != nil {
		return fmt.Errorf("create network: %w: %w", ErrStart, err)
	}
	if res.exit != 0 {
		// A name conflict lands here too: the network is someone else's,
		// and Close removes only networks carrying this run's label.
		return fmt.Errorf("create network (exit %d): %w", res.exit, ErrStart)
	}
	s.network = name
	return nil
}

// networkFor is the --network value of a spec: none, or the run's network
// once it exists.
func (s *Sandbox) networkFor(spec Spec) (string, error) {
	if !spec.networked {
		return "none", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.network == "" {
		return "", fmt.Errorf("no run network yet: %w", ErrSpec)
	}
	return s.network, nil
}

// removeNetworks lists the networks carrying every label and removes them.
// Containers go first (removeLabeled): a network in use is not removed,
// and no --force is passed, which on Podman would remove the containers
// using it, creep's or not.
func removeNetworks(ctx context.Context, run runFunc, st Status, labels ...string) (int, error) {
	list := append(globalArgs(st), "network", "ls", "--no-trunc", "--format", "{{.ID}}")
	for _, l := range labels {
		list = append(list, "--filter", "label="+l)
	}
	res, err := run(ctx, list, infoLimit)
	if err != nil {
		return 0, fmt.Errorf("list %s networks: %w", st.Runtime, err)
	}
	if res.exit != 0 {
		return 0, fmt.Errorf("list %s networks: exit status %d", st.Runtime, res.exit)
	}
	ids, err := parseIDs(res.stdout, res.truncated)
	if err != nil {
		return 0, fmt.Errorf("list %s networks: %w", st.Runtime, err)
	}
	for start := 0; start < len(ids); start += removeBatch {
		if err := removeNetworkIDs(ctx, run, st, ids[start:min(start+removeBatch, len(ids))]); err != nil {
			return start, err
		}
	}
	return len(ids), nil
}

func removeNetworkIDs(ctx context.Context, run runFunc, st Status, ids []string) error {
	res, err := run(ctx, append(append(globalArgs(st), "network", "rm"), ids...), infoLimit)
	if err != nil {
		return fmt.Errorf("remove %s networks: %w", st.Runtime, err)
	}
	if res.exit != 0 {
		return fmt.Errorf("remove %s networks: exit status %d", st.Runtime, res.exit)
	}
	return nil
}
