# ADR 0015: Model CLI presets as embedded data

- **Status:** Proposed
- **Date:** 2026-11-16
- **Deciders:** @Ludocius

## Context

#6 ([ADR 0014](0014-command-model-through-gateway.md)) lets any CLI be the model through `model.run`. Each CLI needs its own non-interactive and tools-off flags (`claude -p --tools "" --strict-mcp-config`, `codex exec --sandbox read-only`, ...), and those flags change with CLI releases. A wrong flag gives a model that reads untrusted code a shell. #7 asks for presets: `model: { preset: claude-code }` resolves the command, presets are community data that need no code change, and every preset passes the tool canary. This adds a config key (`model.preset`), a public contract.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Presets embedded in the binary (`go:embed`), closed YAML schema, resolved in `internal/config` into `model.run` | Nothing on disk to plant or swap; reviewed like code (CODEOWNERS); one path to the gateway (`model.run`), so the #6 checks and the canary apply unchanged; `config explain` shows the command | A new or fixed preset needs a release |
| B. Presets loaded from a user directory (`~/.creep/presets`) or the repository | New CLIs without a release | A file the scanned repository or another local user can plant chooses the program; needs a trust and pinning scheme like recipes (`creep.lock`) |
| C. Preset as a new contract in `internal/models` | Could pass argv without re-quoting | Second path to the gateway beside `model.run`; duplicates #6's checks |

## Decision

A. Presets are embedded data in `internal/presets` (layer 0, no internal imports), resolved by `internal/config` after every layer has applied: the preset fills `model.run` (quoted for the gateway's shell-free splitter) and `contract: command`, and `config explain` names the preset as their source. The deciding reason: a preset picks the program that reads scanned code, so it must not come from anywhere the repository can write.

Rules: the schema is closed (unknown or duplicate keys, a second document, a program that is a path, args as a shell string, control characters are errors); `tools_off` lists every argument run that switches tools off and each must appear in `args` (empty only with `no_tools: true`); `model.preset` and `model.contract` cannot be set in the project file; `model.name` cannot come from the project file when the preset passes it to the CLI (`{model}`), and never starts with `-`; a preset next to `model.run` or a non-command contract is an error, never a silent choice. The tool canary still runs on every preset at `creep doctor` and every scan start.

**Host reads.** The canary sees files written and commands that leave files, never reads. So every preset declares `host_reads: none` (no tool can read outside the empty working directory: `claude-code` with `--tools ""` and no MCP, `ollama run`) or `host_reads: unbounded` with a one-line `host_reads_detail`. `codex` is unbounded: `codex exec` runs shell commands without approval, and `--sandbox read-only` blocks writes and network but not reads, so injected code can make it read `~/.ssh` or `~/.aws` and put the content in a prompt to its provider, past creep's redaction. No codex flag that confines reads to the working directory is documented, so none is set. `gemini` is unbounded: read-only built-in tools (read_file, glob, web fetch, `google_web_search`, which also reaches the web outside creep's gateway) and MCP servers from `~/.gemini/settings.json` may stay enabled in headless mode. `creep doctor` and every scan print an escaped warning for an unbounded preset before the canary runs. This qualifies ADR 0014's "Reading is bounded: the working directory is empty", which holds only for CLIs with no read tools.

## Consequences

- Adding or fixing a preset is a data-only PR (`internal/presets/<name>.yaml`) with the manual canary check from CONTRIBUTING.md; `TestEmbeddedPresets` validates every file in `make check` and CI.
- A CLI flag change needs a creep release. Users can still write `model.run` themselves meanwhile.
- `internal/presets` is a CODEOWNERS path; review checks each flag against the CLI's documentation.
- Residual (threat model §4.2a C6): a CLI's own settings (hooks, MCP servers, read-only tools) are outside the preset; the canary catches writes and commands, not reads. `codex` and `gemini` are `host_reads: unbounded` and warn at every run; for untrusted code the docs recommend `claude-code` or `ollama`. A codex or gemini flag that confines reads would let a later preset change move them to `none`.
