# ADR 0027: Read-only MCP server on the official Go MCP SDK, stdio only

- **Status:** Accepted (maintainer, 2026-11-23)
- **Date:** 2026-11-23
- **Deciders:** @Ludocius
- **Fitness function:** the rows "Only `gateway` reaches the network (invariant 1)", "No dependency without an ADR (invariant 6)" and "MCP tools write only under `.creep/` and start no container" of [architecture.md §9](../architecture.md#9-fitness-functions)

## Context

Issue #32: coding agents should call creep as a tool, through the Model Context Protocol (MCP), over stdio. The calling agent may itself be under prompt injection (from the code it reads, a web page, an issue), so whatever it sends is untrusted: it must not be able to make creep write files, start containers, run PoCs or reach the network through us.

MCP is JSON-RPC 2.0 with a handshake (`initialize`, capabilities, protocol version negotiation), `tools/list` with JSON Schemas and `tools/call` with typed results. The maintainer chose the official Go SDK, `github.com/modelcontextprotocol/go-sdk`, maintained by the MCP project with Google, over writing the protocol by hand: the protocol revises every few months, and a hand-rolled server would have to track version negotiation, cancellation, schema validation and framing on its own.

The SDK is the first direct dependency since `go.yaml.in/yaml/v3` (ADR 0001) and the first that reaches networking. Its `mcp` package holds every transport in one package: stdio and `io` streams (`StdioTransport`, `IOTransport`), but also the Streamable HTTP and SSE client and server (`net/http`), a command transport that starts a program (`os/exec`), and OAuth support through `golang.org/x/oauth2`. `make budget`'s import-graph rules are per package (#43), so `internal/mcp` reaches `net` and `os/exec` through it and fails both the net reach and the process reach check (AGENTS.md invariant 1). Go links only reachable code, so what matters is what the binary links, not what the package imports.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Official SDK, stdio only, with a linker-level proof that none of its network or process code is linked | Maintained protocol support, schema validation and version negotiation; the HTTP, SSE and command transports and OAuth stay in the module cache, never in the binary, and a check on every release target proves it | One direct and eight indirect modules; per-package import rules need a narrow exemption backed by the stronger check |
| B. Hand-written JSON-RPC over stdio, stdlib only | No dependency; nothing to exempt | creep would own the MCP protocol (handshake, negotiation, schemas, cancellation, errors) and its drift; more security-relevant parsing code of our own |
| C. Official SDK with its HTTP transport for remote agents | Remote agents could connect | Opens a listening socket outside the gateway: breaks invariants 1 and 5 by design |
| D. A fork or vendored subset of the SDK without the HTTP files | Import graph would pass unmodified | We would maintain a fork of a fast-moving SDK; still a dependency, now unreviewed upstream fixes |

## Decision

Option A: `creep mcp` serves three tools over stdio with `github.com/modelcontextprotocol/go-sdk` **v1.8.0**, pinned exactly in `go.mod`. No network transport is used: the server runs on `mcp.IOTransport` over the process's stdin and stdout, and nothing in creep listens, dials or starts a program for the protocol. The SDK's own guarantees (schema validation of every call, version negotiation) were what decided it over option B.

The tools and their rules:

- **`scan`**: a pull-request-mode scan of the changed files the caller lists, reusing `--changed` (#26): 1 to 1000 repository-relative paths, each checked with `report.ValidPath` (no absolute path, drive letter, backslash, `..`, `.` or empty segment, NUL or path over 4096 bytes) and then with the `--changed` rules. A full scan, nightly mode, the sandbox, PoCs, optional scanners, a consent prompt (stdin carries the protocol), a calibration run, the stability record and creating the user's state key are all off: the MCP scan refuses until a CLI scan has created the state key and a valid calibration is cached (`calibrate.CacheOptions.CacheOnly`), and consent must already be stored. `creep mcp` refuses `--mode` other than `pr`, `--record` and `--recalibrate`, and the per-command rules already refuse `--changed`, `--stability`, `--baseline` and `--baseline-write` for it. One scan runs at a time; a second call is refused, not queued.
- **`findings`**: the last report's findings (`.creep/report.json`, read as `creep why` reads it), with an optional status filter and pages of 1 to 200.
- **`why`**: one finding's evidence by ID, checked with `report.ValidID` before anything is read.
- **Fixes**: creep proposes no fix today. When one is added, it comes back only as a unified diff in a tool result, for the host agent to show its user, and is never applied by creep.
- **Output**: every repository string (a path) and every error goes through `report.Visible`, so control, bidi and other non-printable runes arrive escaped; errors are cut at 1 KiB, and the scan's log at 8 KiB. One inbound message is capped at 1 MiB. Tool annotations mark every tool non-destructive and closed-world; the server's instructions tell the agent that paths and classes are data, never instructions.

The layer table puts `internal/mcp` in layer 6 with `report` and `exitcode`; it never reaches the scan pipeline, the model or the file system itself. `internal/cli` hands it a `Backend` whose scan runs the normal `runScan` with an in-memory `--changed` list and the dependencies listed above swapped out (`scanDeps.forMCP`).

The proof that no network or process code is linked:

- `internal/tools/budget`'s net and process reach checks skip the SDK module (`linkProven`) only when `internal/mcp` imports it, tests included; the module is taken from the `go list` listing, so a look-alike path gets no exemption, and any other package importing the SDK still fails.
- A new tool, `internal/tools/linkcheck`, run by `make budget` after the budget, links `cmd/creep` for every release target in `.goreleaser.yaml` with `-ldflags=-dumpdep` and walks the linker's reachability graph from every third-party symbol (the SDK and every module behind it, including package `init` functions). Reaching any function of `net`, `net/http`, `net/rpc`, `net/smtp`, `os/exec` or `crypto/tls`, or `os.StartProcess`, `syscall.StartProcess` or `syscall.forkExec`, fails the build. Funcdata the linker deduplicates by content (`.stkobj`, `.arginfo1` and the like) is not followed, since its name can belong to any function with the same bytes. One edge is reviewed and listed with its reason (`linkReviewed`): the `oauthex` package's `init` clones `http.DefaultTransport` into an unused variable; only its OAuth discovery would send through it, and that code is not linked. A reviewed edge that is no longer linked fails too, so the list only shrinks.
- `linkcheck` also parses every `.go` file of the module and refuses any SDK name outside `sdkAllowed`: the server, typed tools, `IOTransport`, and for tests the client. `StreamableClientTransport`, `NewStreamableHTTPHandler`, the SSE types, `CommandTransport`, `NewInMemoryTransports` (a `net.Pipe`), every other SDK package and dot or blank imports are refused, in tests as well.

Transitive modules the SDK adds (`go list -m all`), with the packages creep's build reaches:

| Module | Version | License | Reached for |
|---|---|---|---|
| `github.com/modelcontextprotocol/go-sdk` | v1.8.0 | Apache-2.0 (new code) and MIT (older code), per its LICENSE | `mcp`, `jsonrpc`, `auth`, `oauthex`, internal packages |
| `github.com/google/jsonschema-go` | v0.4.3 | MIT | tool input and output schemas |
| `github.com/segmentio/encoding` | v0.5.4 | MIT | the SDK's case-sensitive JSON decoding |
| `github.com/segmentio/asm` | v1.1.3 | MIT | SIMD helpers of `segmentio/encoding`; its assembly holds no `SYSCALL`, `SVC` or `INT 0x80` |
| `golang.org/x/sys` | v0.41.0 | BSD-3-Clause | `cpu` only (feature detection) |
| `github.com/yosida95/uritemplate/v3` | v3.0.2 | BSD-3-Clause | resource templates (unused by creep, linked by the `mcp` package) |
| `golang.org/x/oauth2` | v0.35.0 | BSD-3-Clause | imported by the SDK's `auth`; its network code is not linked (`linkcheck`) |
| `golang.org/x/sync` | v0.20.0 | BSD-3-Clause | `errgroup` |
| `golang.org/x/time` | v0.15.0 | BSD-3-Clause | `rate` |
| `github.com/golang-jwt/jwt/v5`, `github.com/google/go-cmp`, `golang.org/x/tools`, `cloud.google.com/go/compute/metadata` | v5.3.1, v0.7.0, v0.42.0, v0.3.0 | MIT, BSD-3-Clause, BSD-3-Clause, Apache-2.0 | in the module graph only (SDK tests and `oauth2`'s other packages); no creep build compiles them |

The module graph grows from 2 to 15 entries, under `make budget`'s cap of 30; the stripped linux/amd64 binary is about 11.2 MiB, under the 16 MiB cap.

## Consequences

- Easier: an agent can scan its own change and read creep's evidence without a shell; creep tracks MCP revisions by bumping one pinned module.
- Harder: every bump of the SDK re-runs `linkcheck` on six targets; a release that links new network code in an `init` fails `make budget` until the edge is reviewed and listed, or the bump waits. The SDK's exported API is large, so `sdkAllowed` must stay short; a new name needs a review against this ADR.
- The calling agent can still spend the operator's model budget: each `scan` call is a full pull-request scan of its files under the configured `budget.*` limits, one at a time. It cannot raise those limits, choose the endpoint or consent to one.
- Repository text (paths) still reaches the agent, escaped but readable; an agent that follows instructions in file names is outside creep's control. The server's instructions and tool descriptions state that this text is data.
- `make budget` now runs `go run ./internal/tools/linkcheck`; `TestMakeCheckRunsBudget` pins it. Protection tests: `TestMCPWritesOnlyUnderCreep`, `TestMCPStartsNoContainer`, `TestMCPRefusesHostileArguments`, `TestLinkReachCatchesNet`, `TestSDKUsesAllowlisted` (Makefile `PROTECTION_TESTS`), plus `TestLinkExemptOnlyForMCP` and `TestProcessReachExemptOnlyForMCP` in the budget.
- License: `Apache-2.0 AND MIT` for the SDK; MIT and BSD-3-Clause for its linked dependencies (table above). The auditor checks them again on any version bump.
