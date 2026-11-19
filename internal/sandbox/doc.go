// Package sandbox finds a local container runtime (Docker or Podman) and
// starts containers only with creep's hardened profile.
//
// It exists because proofs of concept are written by a model that read
// untrusted code, so they must never run on the host (AGENTS.md invariant
// 4). It is one of the few packages allowed to start a program (ADR 0016,
// the execAllowedExact entry in internal/tools/budget), and it never opens
// a connection itself: it runs the docker or podman CLI, which talks to its
// own local daemon. Everything that makes that safe lives here:
//
//   - The runtime binary is found on PATH as the OS would find it; a match
//     in the current directory, a relative PATH entry, the repository or the
//     working directory (final path, links and junctions followed) is
//     refused, and on Windows only an .exe runs.
//   - Docker's endpoint is pinned: DOCKER_HOST or the current context must
//     be a unix socket at an absolute path or a named pipe on this machine,
//     and every later call passes it as --host. A tcp:// or ssh:// endpoint,
//     a pipe on another host, or a Podman that would be a client of a
//     remote service is refused: the sandbox never reaches another machine.
//   - The runtime must run Linux containers with seccomp and memory and pids
//     limits; Detect reports rootless, VM (Docker Desktop) or rootful
//     isolation, rootless first.
//   - The CLI gets a fixed environment (no keys, tokens, proxies or
//     DOCKER_HOST; PATH without relative or repository entries), a working
//     directory outside the repository, no stdin, no stderr and capped
//     stdout.
//   - Arguments come only from fixed builders. Every container runs with
//     --network=none, --cap-drop=ALL, no-new-privileges, a read-only root
//     with a noexec /tmp tmpfs, user 65534, pids, memory and CPU limits,
//     the runtime's default seccomp profile, every proxy variable empty,
//     --pull=never, a digest-pinned image and a per-run timeout. The CLI
//     that runs containers reads an empty DOCKER_CONFIG, so the operator's
//     config.json proxies (and their credentials) never reach a container. Mounts are read-only regular files that
//     creep wrote in the sandbox's own work directory; the Docker socket,
//     sockets in general and host credential paths are refused.
//   - Every container carries creep's labels and its run ID. A timeout or
//     Ctrl+C removes the container (by label, never by name), Close removes the run's containers, and
//     Clean (creep clean) removes every creep container a killed run left.
//
// No runtime is not an error: scans run as before and findings stay
// probable.
package sandbox
