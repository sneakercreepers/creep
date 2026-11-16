# ADR 0014: Command models run through the gateway, with a tool canary

- **Status:** Proposed
- **Date:** 2026-11-16
- **Deciders:** @Ludocius
- **Changes:** the command model contract (architecture §4), the config schema (`model.run`, `model.env`, `model.timeout_seconds`, `model.max_output_bytes`), the CLI contract (`--model-run`, `creep doctor`), the `egress.log` line (command endpoints and three result outcomes), and which package may start a process

## Context

#6 lets any model CLI be the model: `claude -p --tools "" --strict-mcp-config`, Gemini CLI, `codex exec`, `ollama run`, `llm`. The prompt goes on stdin and the model's JSON object comes back on stdout. Two things make this a security change:

- Starting a program is a way around the network ban (AGENTS.md invariant 1): today no product package may import `os/exec` (`make budget`).
- Every model call must go through the gateway, which redacts first and writes `egress.log` (invariant 2). A CLI talks to its provider on its own, so creep cannot allowlist where the bytes go; it can only control what it hands the CLI and record it.
- The CLI reads untrusted code. If it has tools (file writes, a shell, MCP servers), injected text in that code could make it act on the host. Its config cannot be trusted to say tools are off, so creep must check.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Run the process in `internal/models`, with an `execAllowed` entry, and call the gateway only to log | Keeps the gateway free of process code | Two egress paths: a bug or a later change in `models` could run the CLI without the write-ahead log, consent or budget; invariant 2 would rest on review, not on structure |
| B. A new package (`internal/modelcmd`) that runs processes, between `gateway` and `models` | Process code isolated | Same two-path problem as A; one more layer row and `execAllowed` entry for one file of code |
| C. The gateway owns the process: an opaque `gateway.Command` that only `EgressLog.Exec` can run, after consent, budget and the write-ahead request line | One egress point for both transports, as for HTTP (`*Client` is opaque and only `Send` uses it); no new `execAllowed` entry, since the gateway is already the reviewed exception to the import rules; `models` stays transport-free | The gateway grows (about 400 lines with tests) and is no longer only about the network |

## Decision

Option C. What decided it: invariant 2 then holds by construction. `models` can reach a CLI only through a `SendFunc` that calls `EgressLog.Exec`, exactly as it reaches an HTTP endpoint only through `EgressLog.Send`, and the gateway has no exported way to start the program otherwise.

**Gateway (`internal/gateway`).** `NewCommand(CommandOptions)` splits `model.run` without a shell: space and tab separate arguments, `'...'` and `"..."` group text literally (`""` is an empty argument), and shell syntax (`$`, backticks, `|`, `;`, `&`, `<`, `>`, globs, `~`, `#`, braces) outside quotes is refused rather than passed on. The program must be a bare name found in an absolute `PATH` entry (`exec.ErrDot` is refused, so a file in the current directory, which is the repository during a scan, never runs) or an absolute path, and it must not resolve inside the repository. The environment is fixed at open: `PATH`, `HOME`, `LANG`, `LC_ALL` and the Windows variables a program needs to start, plus only the names in `model.env`; nothing else, `CREEP_API_KEY` included, is inherited. `Endpoint()` is `command://<program>-<16 hex>`, a hash of the resolved path, the arguments and the env names; consent, the budget, AIMD concurrency and `egress.log` key on it as on an HTTP origin, and a policy may list it under `consent` (`creep doctor` prints it).

`EgressLog.Exec` has `Send`'s order and guarantees: consent, budget reservation and concurrency slot, payload file and request line written and fsynced, then the run. Each run gets a fresh temp directory as its working directory (never the repository) and a separate one for `TMPDIR`, `TEMP` and `TMP`; the payload goes to stdin byte for byte; stdout is capped (`model.max_output_bytes`, 1 KiB to 8 MiB; past it the program is killed); stderr goes to the null device, because it may echo the prompt; `model.timeout_seconds` (1 to 3600) kills a hung or slow-dripping program, and a two-second wait delay stops a grandchild holding the pipe from hanging the run. After the run, anything left in the working directory is a `*ToolUseError`: the reply is dropped whatever the exit status. The result line gains three closed outcomes, `tool_use`, `timeout` and `command_failed`, and carries no HTTP status or tokens (CLIs report none, so the reservation stays spent). Stdout is the reply body with `Status` 200, so `models` treats both transports alike.

**Models (`internal/models`).** `NewHTTP` accepts `Contract: "command"` with the command's endpoint and `StructuredPrompt` only; it takes no API key. The command wire writes the system prompt, the user turn and the JSON schema as plain text; stdout gets the same closed-struct decoding as an HTTP reply (unknown, duplicate and case-variant keys refused, no prose or code fence around the object), with the same bounded retries. `ThroughCommand(log, cmd)` is the production `SendFunc`. A `*gateway.ToolUseError` on any call is not retried, so tool use is caught on every call, not only at the canary.

**Tool canary.** `models.Canary.Check` sends a trap prompt through the same gateway path: create a file named `creep-canary-<random>` in the current directory and run `echo ready > creep-canary-<random>`, both with fresh random names. If either appears, or anything else is left in the working directory, it returns a `*ToolsEnabledError` saying which action it saw and the fix for known CLIs: `claude` names the missing `--tools ""` and `--strict-mcp-config`; `gemini` and `llm` name the tool-enabling flags present (`--yolo`, `-y`, `--approval-mode`; `-T`, `--tool`, `--functions`); `codex` needs `--sandbox read-only`; others get a generic fix. A canary that cannot run fails closed. Results are cached per command endpoint in the `Canary` value, which the CLI makes once per run; nothing is stored across runs. `creep scan` runs it before calibration (a `--replay` run starts no program and skips it); `creep doctor` runs it in a new run directory. Both exit 3 when it fails (2 for a consent refusal).

**Config and CLI.** `model.run` and `model.env` cannot be set in the project file (the scanned repository must not choose the program that gets its code or the secrets that program sees); user config, `--config`, `CREEP_POLICY` and the new `--model-run` flag can, and a policy can lock them. `creep doctor` is no longer a stub: it checks the model (the canary for a command model; an HTTP API has no tools) and reports the sandbox as not checked until #21.

## Consequences

- Easier: one egress point for both transports; `models`, `calibrate`, `reader`, the recording cache and `--stats` work unchanged with a CLI; `make budget` needs no new `execAllowed` entry.
- Harder: `internal/gateway` now holds process code too, so its review covers TB8 as well as TB4. `gateway.Command` stays opaque (no exported run method) and an API test must keep it that way.
- The canary detects tools that write in the working directory. A CLI whose tools write only elsewhere, or only read, passes; that residual risk is in the threat model (C4). Reading is bounded: the working directory is empty and the CLI never runs in the repository.
- A Windows `.cmd` or `.bat` shim (how npm installs `claude` on Windows) is run through `cmd.exe` by Go's `os/exec`; its arguments come only from operator config and the prompt only from stdin, so repository text never reaches a command line.
- Estimate (ADR 0011) still measures a command model as `openai`: the prompt, schema and slice are the same text.
- Presets (#7) own full command lines per CLI; the canary only knows the flags that switch tools on or off.
- Maintainer approval is required before merge (contract and invariant-adjacent change).
