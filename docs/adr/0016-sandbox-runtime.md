# ADR 0016: Drive Docker or Podman through their CLI from one package

- **Status:** Accepted (maintainer approval 2026-11-19)
- **Date:** 2026-11-19
- **Deciders:** @Ludocius
- **Changes:** the exec rule in `internal/tools/budget` (one new package, `internal/sandbox`, matched exactly); the layers table (`sandbox` moves to layer 5 and imports `static`; `verify` and `mcp` move to 6, `cli` to 7, `cmd/creep` to 8); the CLI contract (`creep clean`, the sandbox section of `creep doctor`, one stderr line in `creep scan` when `sandbox.enabled`)

## Context

#21 needs a container runtime: PoCs are written by a model that read untrusted code, so they must run only in a container (AGENTS.md invariant 4), never on the host. The issue asks for Docker and Podman (rootless preferred) through their Docker-compatible API, a hardened profile for every container, per-run labels, cleanup on exit and Ctrl+C, `creep clean` for orphans, a synthetic `.env`, and never the Docker socket or host credentials inside a container. With no runtime, a scan must still succeed and findings stay `probable`.

Talking to a runtime collides with two rules:

- The Docker-compatible API is HTTP over a unix socket (`/var/run/docker.sock`, `$XDG_RUNTIME_DIR/podman/podman.sock`) or a Windows named pipe. Speaking it from creep needs `net` (and `net/http`), which only `internal/gateway` may import (invariant 1), and it is a connection to something that is not a model endpoint (invariant 5).
- Running the `docker` or `podman` CLI needs `os/exec`, which only `internal/gateway` (model CLIs, ADR 0014) and `internal/scanrun` (ADR 0013) may import.

Facts that shape the profile (from `docker run --help`, `podman run --help`, `docker info`, `podman info` and a Docker Desktop 29.7 check on the dev machine):

- Both CLIs take the same run options for everything the profile needs: `--network=none`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--read-only`, `--tmpfs`, `--user`, `--pids-limit`, `--memory`, `--memory-swap`, `--cpus`, `--ipc=private`, `--pull=never`, `--label`, `--mount=type=bind,...,readonly`.
- A tmpfs from `--tmpfs` is not world-writable unless it says `mode=1777`; a non-root user cannot write `/tmp` otherwise (found by the integration test).
- `docker info` reports `SecurityOptions` (`name=seccomp,profile=...`, `name=rootless`), `OSType`, `OperatingSystem` (`Docker Desktop`) and whether memory, pids and CPU limits work. `podman info` reports `host.security.rootless`, `host.security.seccompEnabled`, `host.serviceIsRemote` and `host.cgroupControllers`.
- The Docker CLI's endpoint comes from `DOCKER_HOST` or the current context, and can be `tcp://` or `ssh://`. `docker context inspect --format '{{json .Endpoints.docker.Host}}'` prints it; `--host` pins it for one call.
- Killing `docker run` does not stop its container, so cleanup must remove containers by name or label.
- `docker run` adds the proxies of the client's `config.json` (credentials in the URL included) to every container's environment unless the variable is set explicitly; Podman copies the host's proxy variables unless `--http-proxy=false`.
- Docker 29 has `--use-api-socket`, which mounts the API socket into the container.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Speak the API from `internal/gateway` over the socket | No CLI dependency; structured answers | The gateway becomes a container client as well as the model egress point; it opens a non-model connection (invariant 5); HTTP over a unix socket and a named pipe without `x/sys` or `unsafe` is new code in the most sensitive package |
| B. Speak the API from `internal/sandbox` with a `net` reach exception | Gateway untouched | Breaks invariant 1 for a second package; the exception would cover `net` in general, not only the runtime socket |
| C. `internal/sandbox` runs the docker or podman CLI through `os/exec`, matched exactly like `scanrun`; one fixed argv builder per call; no `net`, no socket opened by creep | No network code outside the gateway; the exec exception is one package wide, as for scanrun; the CLI already handles contexts, rootless sockets and Docker Desktop's pipe | Depends on CLI flags and their output formats; the CLI is the operator's program, so its plugins and telemetry are outside creep's control |

## Decision

Option C. What decided it: it is the narrowest exception. creep opens no socket and imports no `net`; the only new power is starting two known programs with arguments only this package builds, the same shape `scanrun` was approved with.

**Which binary.** `exec.LookPath` finds `docker` and `podman` as the OS would; `exec.ErrDot` (current directory, relative entry) is refused, and the match must pass `static.OutsideRepo` (final path, links and junctions followed, compared with the repository and the working directory by file identity, ADR 0013). On Windows only an `.exe` runs. `sandbox` imports `static` for that check, so it moves to layer 5 beside `scanrun`; `verify`, which imports `sandbox`, moves to 6, and so do `mcp` (to stay below `cli`), `cli` to 7 and `cmd/creep` to 8.

**Which endpoint.** Docker: `DOCKER_HOST` if set, else the endpoint of `DOCKER_CONTEXT` (a plain name only) or the current context. Only a `unix://` socket at an absolute path and a named pipe on this machine (`npipe:////./pipe/<name>`; a pipe on another host is a UNC path opened over SMB) are accepted, and every later call passes it as `--host`; `DOCKER_HOST` itself is never passed to the CLI. Podman runs locally only: outside Linux, or with `CONTAINER_HOST` or `CONTAINER_CONNECTION` set, it is refused without being started; every Podman call carries `--remote=false`; a service that still reports `serviceIsRemote` is refused. No `tcp://`, `ssh://` or remote connection is ever used.

**Which runtime is usable.** Linux containers, seccomp on and not unconfined, and memory, pids and CPU limits available. Isolation is `rootless` (Docker rootless or Podman rootless), `vm` (Docker Desktop: the daemon runs in a VM) or `rootful`; detection checks the configured runtime (`sandbox.runtime`) first and picks the strongest isolation, the configured one on a tie. A rootful daemon is usable, and `creep doctor` warns about it.

**How the CLI runs.** `exec.CommandContext` with the final path and arguments from fixed builders (`context inspect`, `info`, `run`, `ps`, `rm`); no shell. The environment is fixed: `PATH` without relative entries or entries in the repository or working directory (Podman finds `conmon` on it), the home and XDG directories, `DBUS_SESSION_BUS_ADDRESS`, `DOCKER_CONFIG`, the Windows start-up variables, `DOCKER_CLI_HINTS=false` and `LC_ALL=C`; no keys, tokens, proxies or `DOCKER_HOST`. The operator's `DOCKER_CONFIG` serves detection only (the current context); the CLI that runs and removes containers gets an empty `DOCKER_CONFIG` in the work directory, since the endpoint is already pinned. Every container also gets each proxy variable set empty (both cases), Podman `--http-proxy=false`, and a spec cannot set a proxy variable. The working directory is the temp directory, stdin is empty, stderr goes to the null device (it carries container output too), stdout is capped (1 MiB), and a timeout plus a two-second wait delay bound every call. Answers are decoded into closed structs; container lists become `rm` arguments only as hex IDs.

**The hardened profile.** One builder makes every `run` command line: `--rm`, `--name=creep-<run>-<n>`, `--pull=never`, `--network=none`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--read-only`, `--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777`, `--user=65534:65534`, `--pids-limit=128`, `--memory=512m`, `--memory-swap=512m`, `--cpus=1`, `--ipc=private`, the labels `io.github.sneakercreepers.creep.managed=true` and `io.github.sneakercreepers.creep.run=<run ID>`, then the spec's env as `--env=NAME=value` (checked names, no line breaks; a bare name, which would copy the host's value, cannot be written), its mounts, the image and its command. The values are constants, not config: nothing may loosen them. The image must be pinned (`name@sha256:<hex>` or a local `sha256:<hex>` ID) and present; pulling is a separate, later step. Seccomp is the runtime's default profile, required at detection; creep ships no profile of its own. Each container has a timeout (default 1 minute, at most 10).

**Mounts and the synthetic `.env`.** A mount is a read-only bind of one regular file below the sandbox's own work directory (`os.MkdirTemp`, 0700), with no link, junction, socket or device on the way, and no runtime socket name (`docker.sock`, `podman.sock`, `/run`, `/var/run`, Windows pipes) or credential name (`.ssh`, `.aws`, `.docker`, `.kube`, `.gnupg`, `.netrc`, `.git-credentials`, `gcloud`, creep's state) anywhere in the path, before or after links resolve. `--volume`, `--env-file` and `--use-api-socket` are never built. `WriteSyntheticEnv` writes a `.env` with a random `creep-synthetic-…` value per name for an app under test to read instead of a real one.

**Cleanup.** A timeout, Ctrl+C (caught only while a container runs, so the container is removed and `Run` returns `ErrInterrupted`) a canceled run or a refused start removes the container by its run label and a per-container label carrying its name, never by name alone (a name conflict may be another program's container); `Close` removes the run's containers by label and the work directory; `creep clean` removes every creep-labeled container on every reachable local runtime. A creep that is killed leaves its containers until `creep clean`.

**CLI.** `creep doctor` lists each runtime (path escaped, reason as an ID) and the one a scan would use with its rootless status and isolation; a missing runtime is not an error. `creep clean` exits 0 when every reachable runtime was cleaned (or none is reachable) and 3 when a removal failed. `creep scan` with `sandbox.enabled` prints one line saying whether a runtime was found; nothing is verified until #22, so findings stay `probable` and the exit code is unchanged. `sandbox.*` stays an operator-only setting (the project file cannot set it).

## Consequences

- `internal/tools/budget` gains `internal/sandbox` in `execAllowedExact` (no subpackages); `net`, `net/http` and `syscall` stay forbidden there, and tests pin all three (`imports_test.go`).
- Protection tests in `make protections`: `TestEveryContainerIsHardened` (every `run` line holds the profile and nothing outside an allowlist), `TestHardeningCheckCatchesWeakenedRun` (the check fails on each weakened line), `TestMountRefusesHostPaths`, `TestOperatorProxiesNeverReachContainers` (the operator's `config.json` proxies never reach `run`, and the broken path is caught). The integration tests (`integration_test.go`) run a probe built from `testdata/probe` inside a real container and kill a child creep to prove `creep clean` removes the orphan; they skip where no runtime is usable, except in CI on Linux, which sets `CREEP_REQUIRE_SANDBOX=1` so a skip fails. The probe also fails when the environment holds anything beyond the spec's and the runtime's own variables, when a proxy variable is non-empty, or when a pids, memory or CPU limit cannot be read.
- Residual risks (threat model §4.6): a rootful daemon is allowed with a warning; a kernel or runtime escape is out of creep's hands; the CLI's plugins and telemetry belong to the operator; `creep clean` also removes the containers of a run in progress; podman machine (macOS, Windows) is unsupported until a later issue shows its connection is local; a Podman `containers.conf` `env` entry is the operator's own setting and still reaches containers.
- #22–#25 build on this package: an internal network (`--internal`, labeled and cleaned the same way), image builds that leave the repository's `.env*` files out, pulls by digest only. Each needs its own review of the arguments it adds.
- If the CLIs change flag names, `run` fails (exit 125) and the container is removed; no weaker command is tried.
