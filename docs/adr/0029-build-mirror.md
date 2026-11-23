# ADR 0029: Operator-provided mirror network for the app build

- **Status:** Accepted (maintainer, 2026-11-23)
- **Date:** 2026-11-23
- **Deciders:** @Ludocius
- **Amends:** [ADR 0016](0016-sandbox-runtime.md) (the offline-build amendment, #23, whose maintainer decision of 2026-11-20 deferred this mode to v0.3)
- **Changes:** two config keys, `sandbox.mirror.bridge` and `sandbox.mirror.proxy` (operator layers only: user file, `--config`, `CREEP_POLICY`, flags; never `./creep.yaml`); the Podman `build` command line when a mirror is set (`--network=<bridge>` in place of `--network=none`, and four proxy build arguments); one new closed build reason, `mirror_refused`, in the report's verification reasons (ADR 0009's closed set gains one value); the scan's stderr line names the build mode. No new dependency, package, network path in creep's own process, or exit code.

## Context

#277: since v0.2 the app build is offline only (ADR 0016 amendment, #23): `--network=none` for every RUN step, base images only from the local store, no build argument. A project whose build installs packages from a registry is `verification unavailable` (`build_failed`). The issue asks for registry access only through an allowlisted mirror or proxy that the user or org policy configures, while keeping invariant 1 (only `internal/gateway` opens network connections), and the run phase with no network.

Facts that shape the design, checked on Docker 29.7.2 (BuildKit) and from Podman's documentation:

- BuildKit's `--network` accepts only `default`, `none` and `host`. `docker build --network=<user-defined network>` fails: `network mode "x" not supported by buildkit - you can define a custom network for your builder using the network driver-opt in buildx create`. A docker-container buildx builder could join one, but it needs a privileged `moby/buildkit` container, has its own image store (local base images are invisible to it, so `FROM` would pull) and its own lexer version; the legacy builder is deprecated and does not read the forms the Dockerfile check models (`RUN --mount`).
- `podman build --network=<name>` runs RUN steps on a user-defined network. Buildah gets the `HTTP_PROXY` family as build arguments without an `ARG` in the Dockerfile and keeps them out of the image history; BuildKit does the same.
- An allowlisting proxy on a network with a route out is not an allowlist: a RUN step can ignore the proxy variables and connect directly. Only a network with no route out (`--internal`) makes the proxy the only way out.
- A rootful Podman bridge keeps a gateway address in the host's namespace (ADR 0016 amendment, `ErrHostReachable`), so a build step on it could reach local services.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. The mirror runs inside creep, through `internal/gateway`: creep listens on a socket the build can reach and forwards allowed requests | creep owns the allowlist and logs each request | creep would accept connections from hostile build steps and parse their HTTP (a new trust boundary in creep's own process); the gateway is a client for model endpoints, and invariant 5 allows no network calls except to configured model endpoints; the build still needs a network the builder honours, so it would not lift the BuildKit limit |
| B. creep runs a pinned proxy container on a network it creates | One command for the operator | creep would own a proxy's allowlist and an image with egress (invariant 5); BuildKit still cannot use the network |
| C. The operator provides the mirror: an internal network they created with their own mirror or allowlisting proxy on it, named in operator config; creep checks the network (inspect and canary) and runs only Podman builds on it | creep opens no connection and holds no allowlist; the network, not the proxy's good behaviour, stops any other host; the offline default is untouched | Docker users get no mirror mode (BuildKit); the operator must create and run the network and mirror; the allowlist is only as good as the operator's mirror |

## Decision

Option C. What decided it: it is the only option where "a build that tries a host outside the allowlist fails" is enforced by the network the engine puts RUN steps on, it adds no network path to creep's process (invariants 1 and 5), and it keeps every offline check.

**Where the mirror runs.** Outside creep, run by the operator. creep never connects to it, resolves its name or reads its answers: RUN steps inside the builder do. The allowlist is the operator's mirror or proxy configuration; creep's job is to prove the network gives RUN steps no other way out.

**Config.** `sandbox.mirror.bridge`: the name of an existing network (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`, not a network mode: `none`, `host`, `bridge`, `default`, `private`, `slirp4netns`, `pasta`, `podman`, `container`, `ns`, any case). `sandbox.mirror.proxy`: optional, `http://host[:port]` or `https://host[:port]` with an optional trailing slash, so no credentials, path or query; a refused value is not printed. Both are in `projectForbidden`, like `sandbox.enabled`: only the user file, `--config`, `CREEP_POLICY` and flags set them. Both empty (the default) keeps the build offline. `sandbox` checks both again before a build; a proxy without a bridge is refused there.

**Checks before each build**, after every existing check (build file, Dockerfile allowlist, staged context, base images present locally) and before the `build` call; any failure is `mirror_refused` with a closed detail and no build:

1. Runtime: Podman only (`builder` for Docker, since BuildKit cannot join the network), and rootless only (`rootful`).
2. Setting: well formed as above (`config`).
3. Network: `network inspect --format {{.Driver}}/{{.Internal}}/{{.IPv6Enabled}} <bridge>` through the pinned endpoint must print exactly `bridge/true/false`: an internal bridge with no IPv6, the family the canary does not test (`missing` when inspect fails, `not_internal` otherwise).
4. Canary: the pinned BusyBox canary of ADR 0016's run network runs on the bridge with the hardened profile and its own alias: its controls must reach itself, and a public resolver, a public name and two public addresses must stay unreachable (`leak`, or `canary` when inconclusive). The canary does not use the proxy, so a route out the operator left open fails it.

**Build line.** On a mirror build only `--network=none` becomes `--network=<bridge>`, and, with a proxy, `--build-arg=HTTP_PROXY=<proxy>`, `HTTPS_PROXY`, `http_proxy` and `https_proxy` are added. Everything else stays as ADR 0016 sets it: `--pull=never` (base images never come from the mirror), `--http-proxy=false` (the host's proxy variables never reach the build), `--no-cache`, `--layers=false`, `--force-rm`, the memory and CPU limits, creep's labels, the empty `DOCKER_CONFIG`, the staged context and the 15-minute timeout. The Docker build line ignores the mirror, so no change to it is possible.

**Unchanged.** The Dockerfile check (directives, `RUN --network`, remote `ADD`, images, engine-escape rules) and the minimum engine versions apply to mirror builds exactly as to offline ones. The run phase never joins the operator's network: `StartApp`, the database and PoCs use only the run's own internal network after its canary. A refused or failed build is a closed reason, never an error, so it never fails the scan.

## Consequences

- Projects whose builds install packages can be verified on rootless Podman when the operator runs a mirror. On Docker a configured mirror is `mirror_refused` (`builder`): verification stays unavailable, as before, and the scan says so.
- New protection tests: `TestBuildMirrorConfined` (the mirrored Podman line differs from the offline one only by the network and the four build arguments; inspect and a hardened canary run first), `TestBuildMirrorRefused` (each refusal starts no build), `TestBuildMirrorKeepsChecks` (Dockerfile and base-image checks still refuse first, without touching the network), `TestDockerBuildLineIgnoresMirror`, `config.TestProjectCannotSetBuildMirror`, `config.TestMirrorValuesChecked`; `TestRealMirrorBuild` on real engines (on Docker the refusal; on rootless Podman a RUN step reaching past the network fails the build, and a routed network is refused). Threat model X23.
- Residual risks: the allowlist is the operator's mirror; a RUN step can reach every host the mirror or proxy forwards to, and anything else attached to the bridge, and can send build-time data there (the build context holds no `.env` or credential file, but the repository's code); the network is checked before the build, not during it, so an operator who reconnects it in between is trusted; the network's own resolver is judged as on the run network (threat model X10); not verified against a live Podman here (none on the development machine or the CI runners at the minimum Buildah version), so the Podman path is covered by command-line tests and the field names follow `podman network inspect`.
