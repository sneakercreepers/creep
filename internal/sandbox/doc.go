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
//   - The runtime must run Linux containers with seccomp and memory, pids
//     and CPU limits; Detect reports rootless, VM (Docker Desktop) or rootful
//     isolation, rootless first.
//   - The CLI gets a fixed environment (no keys, tokens, proxies or
//     DOCKER_HOST; PATH without relative or repository entries), a working
//     directory outside the repository, no stdin, no stderr and capped
//     stdout.
//   - Arguments come only from fixed builders. Every container runs with
//     --network=none (or the run's internal network, below), --cap-drop=ALL, no-new-privileges, a read-only root
//     with a noexec /tmp tmpfs, user 65534, pids, memory and CPU limits,
//     the runtime's default seccomp profile, no log file (--log-driver=none),
//     every proxy variable empty, --pull=never, a digest-pinned image and a
//     per-container timeout. An image that declares a VOLUME is refused, since its
//     volume would be writable past --read-only, unless a tmpfs of the
//     package's own (the database's data) covers it.
//   - The CLI that runs containers reads an empty DOCKER_CONFIG, so the
//     operator's config.json proxies and their credentials never reach a
//     container. Detection and Clean, which start no container, keep the
//     operator's DOCKER_CONFIG.
//   - Mounts are read-only regular files that creep wrote in the sandbox's
//     own work directory; the Docker socket, sockets in general and host
//     credential paths are refused.
//   - PoCs (RunBatch) and the database (StartDatabase) run on one network
//     per run, creep-<run>: --internal, IPv4 only, and on Docker a bridge
//     with no host address, so no port is reachable from the host; no
//     option that publishes a port is ever built, and rootful Podman,
//     whose bridge keeps a host address, gets no network. Before each
//     batch a canary container (pinned BusyBox) must fail to reach a
//     public IP over TCP and to resolve a public name, through the
//     network's resolver and directly over UDP, while it reaches itself on
//     the network; anything else aborts the run for good.
//   - The database is a pinned PostgreSQL seeded only with the project's
//     SQL migrations (MigrationPaths picks them): the seed is its only
//     mount, its data directory is a tmpfs over the image's VOLUME, and its
//     credentials are random placeholders. creep never pulls an image.
//   - The app is built (Build) only from the repository's own root compose
//     file or Dockerfile, never a generated one and never through
//     `docker compose`: creep reads the compose file for one service's
//     context, Dockerfile and target and refuses every other build key,
//     checks the Dockerfile for anything the builder would fetch (an ADD
//     URL, a syntax frontend, a variable image), requires every base
//     image to be present locally, and builds a copy of the context made
//     in its work directory without .env, git, creep or credential files,
//     with one fixed command line: --network=none, no build arguments,
//     secrets, SSH agent, extra hosts or entitlements, no pull, creep's
//     labels. Anything that stops the build is a closed reason
//     (verification unavailable), never an error; creep scan builds once
//     per run when the sandbox is enabled, with its own file list and
//     reader, and reports the reason (internal/cli). StartApp runs the built
//     image on the run network, after the canary, with the hardened
//     profile.
//   - PoC requests (Exchange, internal/verify, ADR 0019) are raw bytes creep
//     wrote, mounted read-only into one runner container from the pinned
//     BusyBox, started through RunBatch (canary first). Its script is fixed
//     and connects only to the app, on the caller's port; it prints every
//     timing line before any response byte, and the answer is read
//     strictly. DatabaseHasTable looks up only creep's marker table, with a
//     fixed psql query.
//   - Every container carries creep's labels, its run ID and its own name
//     as a label. A timeout or Ctrl+C removes the container by those labels,
//     never by name alone; Close removes the run's containers, built
//     images and network, and Clean (creep clean) removes every creep
//     container, image and network a killed run left.
//
// No runtime is not an error: scans run as before and findings stay
// probable.
package sandbox
