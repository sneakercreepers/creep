<div align="center">

# SneakerCreepers · `creep`

**Find vulnerabilities in your own code with whatever model you have — small or large, local or cloud.**
`creep` measures what your model can actually do, plans around it, sends it only redacted code, and tells you plainly what it did *not* check.

[![Release](https://img.shields.io/github/v/release/sneakercreepers/creep?include_prereleases&sort=semver)](https://github.com/sneakercreepers/creep/releases)
[![v0.2 progress](https://img.shields.io/github/milestones/progress-percent/sneakercreepers/creep/2?label=v0.2)](https://github.com/sneakercreepers/creep/milestone/2)
[![Open issues](https://img.shields.io/github/issues/sneakercreepers/creep)](https://github.com/sneakercreepers/creep/issues)
[![CI](https://github.com/sneakercreepers/creep/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sneakercreepers/creep/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sneakercreepers/creep/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/sneakercreepers/creep/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sneakercreepers/creep/badge)](https://scorecard.dev/viewer/?uri=github.com/sneakercreepers/creep)
[![Go Reference](https://pkg.go.dev/badge/github.com/sneakercreepers/creep.svg)](https://pkg.go.dev/github.com/sneakercreepers/creep)
[![Go version](https://img.shields.io/github/go-mod/go-version/sneakercreepers/creep)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Status](https://img.shields.io/badge/status-v0.1.0%20released-green)

</div>

> [!NOTE]
> **v0.1 is released.** [`v0.1.0`](https://github.com/sneakercreepers/creep/releases/tag/v0.1.0) is the current release; v0.2 is in progress. v0.1 scans **Python (Flask, FastAPI)** and **JavaScript/TypeScript (Express)** only. There is no sandbox yet, so every finding is `probable`, never `verified` (v0.2).

---

## What it does

`creep scan` runs, in order: **calibration** (measures your model per vulnerability class and picks a tier), **static analysis** (tree-sitter routes, sinks and auth), the **planner** (deterministic ranking, no model call), the **reader** (the model reads redacted code slices and answers in a closed schema) and the **report**.

**Guarantees** (fixed; no config key can turn them off — except that the `codex` and `gemini` presets can read host files outside redaction, `egress.log` and `egress.allow`; see Limits):

- **Redaction through the gateway.** Every model call goes through one package that redacts secrets from the whole file before fragmenting it, checks consent and the token budget, and only then sends.
- **`egress.log`.** Every request is written and fsynced before a byte is sent, then its result, with a payload file (mode `0600`).
- **The planner never reads code.** It receives only IDs, enums and booleans, so text in the scanned repository cannot steer it.
- **Honest incompleteness.** Anything not evaluated (unsupported language, unresolved route, skipped sink, failed scanner, budget hit, a file name that is not a clean relative path) is listed and the run exits `4`, never `0`.
- **Model output is never executed** on your machine.
- No telemetry; no network except the model endpoints you configure.

**Limits:**

- Languages: Python (Flask, FastAPI) and JS/TS (Express). Source files in other languages are listed as `unsupported_language` and make the run incomplete, except C, C++, Cython, Vue and Svelte sources shipped inside an installed venv or `node_modules` package, which are listed as `vendor` when they hold no route word. A forged `pyvenv.cfg` or `package.json` can therefore get a first-party C or `.vue` file listed as `vendor` instead of `unsupported_language`; the file is still listed and counted among the files left out by design. A known Express, Flask or FastAPI app or router used other than by a method call, a mount, an export or a few listed reads (passed to a function, stored in an object, destructured, reached through `.call`, `Reflect` or an aliased `getattr`) marks its file `truncated`, so the run is incomplete (`internal/static/escape.go`, `pyescape.go`). Flask and FastAPI routes registered without a decorator (`add_url_rule`, `add_api_route`, `app.route(p)(f)`, a route decorator held in a variable) and sinks reached through `sys.modules` are not seen yet. A repository where static finds no Flask, FastAPI or Express route (Django only, no web code, empty) reports every class not evaluated and exits `4` (`no_routes`).
- Redaction masks secrets by their shape and context. It does not mask a token built by concatenation (`"ghp_" + "..."`), a value under 8 bytes that shows up again without its key, a bare AWS secret key whose key id only appears in a later file, a token disguised with look-alike or invisible characters outside Unicode category Cf (variation selectors, combining marks, Hangul fillers, the braille blank), or a key id that has a format character inside it and is glued to a word by another one. Zero-width and other format characters inside a token are otherwise handled. Full list: [`internal/redact/doc.go`](internal/redact/doc.go) (Detection limits).
- The `codex` and `gemini` presets can read host files outside redaction and `egress.log` (see [Presets](#presets), [ADR 0015](docs/adr/0015-model-presets.md)).
- Known gaps that can let a run read as covered are tracked for v0.2: [#214](https://github.com/sneakercreepers/creep/issues/214).

Design and threat model: [docs/design.md](docs/design.md), [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md).

## Install

### From the GitHub release

Download your archive (linux, darwin, windows · amd64, arm64), `checksums.txt` and `checksums.txt.sigstore.json` from [Releases](https://github.com/sneakercreepers/creep/releases). The current one is [`v0.1.0`](https://github.com/sneakercreepers/creep/releases/tag/v0.1.0).

Verify before running it, with cosign v3+ and the GitHub CLI ([SECURITY.md](SECURITY.md#verifying-a-release)). For `v0.1.0` on linux/amd64:

```sh
cosign verify-blob \
  --certificate-identity 'https://github.com/sneakercreepers/creep/.github/workflows/release.yml@refs/tags/v0.1.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum --check --ignore-missing checksums.txt   # macOS: shasum -a 256 --check --ignore-missing checksums.txt
gh attestation verify creep_0.1.0_linux_amd64.tar.gz \
  --repo sneakercreepers/creep \
  --signer-workflow sneakercreepers/creep/.github/workflows/release.yml
```

A certificate or attestation naming any other workflow, ref or repository means the file was not built by the release workflow: do not run it. Each archive also ships an SPDX SBOM (`<archive>.sbom.json`).

### With Go

```sh
go install github.com/sneakercreepers/creep/cmd/creep@latest
```

Or from source: `git clone https://github.com/sneakercreepers/creep && cd creep && make build`.

## Quick start

Put the model in **your** config (`~/.creep/config.yaml`, `--config` or the org policy), never in the repository's `creep.yaml`:

```yaml
# ~/.creep/config.yaml
model: { preset: claude-code }
```

Then, from the repository root:

```sh
creep config explain   # every effective value and the layer it came from
creep doctor           # runs the tool canary against the model CLI and reports the sandbox runtime
creep estimate         # calls, tokens and time of a scan, without calling a model
creep scan             # scans the current directory; reports in .creep/
creep why <id>         # the evidence behind one finding of the last scan
```

Outside CI, the first send to an endpoint asks for your consent; in CI only the org policy's consent list grants it (`creep doctor` prints the consent key).

### Presets

A preset sets `contract: command` and a reviewed command line with the CLI's tools switched off. Presets are embedded in the binary ([ADR 0015](docs/adr/0015-model-presets.md)).

| Preset | Command line | Reads host files | Verified with the real CLI |
|---|---|---|---|
| `claude-code` | `claude -p --tools "" --strict-mcp-config --output-format text` | no | yes |
| `gemini` | `gemini --skip-trust --approval-mode default --extensions none --allowed-mcp-server-names creep-no-mcp-server --output-format text`. **API key only**: needs `env: [GEMINI_API_KEY]`; Google AI Pro and Ultra moved to Antigravity CLI, which has no preset (see below) | **yes**: tools, policies and include directories from `~/.gemini/settings.json` | no |
| `codex` | `codex exec --sandbox read-only --ignore-user-config -c features.shell_tool=false -c features.view_image=false -c "project_root_markers=[]" --skip-git-repo-check --ephemeral --color never -` | **yes** until checked: the flags that turn off its shell, image tool and user config are unverified; `~/.codex/AGENTS.md` | no |
| `ollama` | `ollama run <model.name> --format json` (needs `name: <model>`) | no | no |

> [!WARNING]
> The tool canary catches writes and commands, not reads. With `gemini` or `codex`, scanned code could steer the CLI to read host secrets (`~/.ssh`, `~/.aws`) and send them to its provider **unredacted, outside `egress.log`**. `gemini` denies `web_fetch` in headless mode and sends `google_web_search` queries to Google, its provider, but a tool or policy your `~/.gemini/settings.json` allows could reach any address outside `egress.allow`. This is an accepted residual risk (ADR 0015, threat model C6, [#229](https://github.com/sneakercreepers/creep/issues/229)): creep only warns at `creep doctor` and every scan, as it does for unverified presets. Do not use them on untrusted code or on a machine whose home directory holds secrets; prefer `claude-code` or `ollama`.

The `gemini` preset needs a Google AI Studio key: a personal Google login fails in headless mode ("This client is no longer supported for Gemini Code Assist for individuals"). Declare the key in `model.env` so it reaches the CLI (creep passes only a minimal environment plus `model.env`):

```yaml
# ~/.creep/config.yaml
model:
  preset: gemini
  env: [GEMINI_API_KEY]
```

It runs with `--skip-trust` because headless Gemini CLI exits 55 in an untrusted folder; the folder it trusts is the fresh, empty directory creep makes for each call, which holds no settings, `.env` or `GEMINI.md`. Gemini also reads the first `.env` above it and `GEMINI.md` files up to a `.git`, so that directory lives under your cache directory (`<user cache>/creep/model`, 0700), never under the shared system temp directory, and creep refuses to run the CLI unless every directory from there up to your home directory is a real directory (no link) that other users cannot write to. Above home nothing is checked (on Windows any user can create folders in `C:\`), so creep also puts empty `.env`, `.gemini/.env` and `.git` files next to the working directory: Gemini stops at the first env file and at the first `.git`, so it reads neither a planted `C:\.gemini\.env` nor your own `~/.env` or `~/.gemini/.env`, so put `GEMINI_API_KEY` in `model.env`. For `codex`, declare `env: [CODEX_API_KEY]` or log in with `codex login`.

**No `antigravity` preset.** Antigravity CLI (`agy`), which replaced Gemini CLI for Google AI Pro and Ultra, is an agent with file, shell, browser and MCP tools, and its documentation has no flag that switches them off, pins the approval mode or skips the user settings file (`~/.gemini/antigravity-cli/settings.json`); headless runs soft-deny only the tools that would ask, so the user's settings decide what runs. `--sandbox` confines shell commands only (file, browser and MCP tools stay under the settings) and has no effect where the OS sandbox is unavailable; stdin input is NDJSON (`--input-format stream-json`), not a plain prompt. A preset must switch tools off with its own flags, so creep ships none ([ADR 0015](docs/adr/0015-model-presets.md), [#258](https://github.com/sneakercreepers/creep/issues/258)). Pointing `model.run` at `agy` yourself is at your own risk; the tool canary still runs, but it cannot see reads.

> [!IMPORTANT]
> The model reads untrusted code, so it must not have tools. `creep doctor` and every scan send a **tool canary** first and stop with exit `3` if the CLI writes a file or runs a command.

### HTTP contract instead

Any OpenAI-compatible endpoint or the Anthropic Messages API. The key comes only from the `CREEP_API_KEY` environment variable.

```yaml
# ~/.creep/config.yaml
model:
  contract: openai          # or anthropic
  endpoint: https://api.example.com/v1
  name: <model>
egress:
  allow: [api.example.com]
```

Your own CLI also works with `contract: command` and `run:` (prompt on stdin, JSON on stdout), or `--model-run <cmd>`. It runs only through the gateway: no shell, an empty private directory under the user cache directory, a minimal environment, a timeout and an output cap ([ADR 0014](docs/adr/0014-command-model-through-gateway.md)).

## Commands and flags

| Command | What it does |
|---|---|
| `creep scan` | Scan the current directory; write `.creep/report.*` |
| `creep estimate` | Build every request a scan would send and measure it; no model call, no network ([ADR 0011](docs/adr/0011-estimate-and-stats.md)) |
| `creep why <id>` | Show the evidence behind a finding of the last scan |
| `creep doctor` | Check the model (a command model must pass the tool canary) and the sandbox: runtime, rootless status, isolation level |
| `creep clean` | Remove every container creep left on local Docker or Podman, for example after a killed run ([ADR 0016](docs/adr/0016-sandbox-runtime.md)) |
| `creep config explain` | Show each effective config value and its source layer |
| `creep version` | Print version, commit and Go version |

`creep init` and continuing a run with `creep resume` are not implemented yet and fail closed.

The sandbox is optional. `creep doctor` lists Docker and Podman with their isolation (rootless first, then a Docker Desktop VM, then a rootful daemon, which it warns about). Only a local socket or named pipe is used, never a `tcp://` or `ssh://` endpoint. Every container runs with no network, no capabilities, a read-only root, user 65534, pids, memory and CPU limits and a timeout, and never mounts the Docker socket or host credentials. Without a usable runtime, scans run as before and findings stay `probable`. PoC verification is not built yet (#22).

| Flag | Effect |
|---|---|
| `--config <path>` | Use this file instead of the user and project files (the policy still applies) |
| `--model-run <cmd>` | Model CLI for the command contract |
| `--record` / `--replay` | Record every model response / serve only recorded responses, never the network |
| `--recalibrate` | Calibrate again even if a calibration is cached (30 days) |
| `--stats` | `scan`: print phase times, model calls, cache hits and tokens |
| `--price-in <n>` / `--price-out <n>` | `estimate` and `--stats`: price per 1M input/output tokens, for a cost |
| `--format`, `--log-level` | Output format (`text`, `json`, `sarif`, `markdown`) and log level |

## Output and exit codes

`creep scan` writes `.creep/report.json` ([schema v1](docs/schemas/report-v1.json)), `.creep/report.sarif` and `.creep/report.md`, per `report.formats`. Reports from earlier runs are removed before each run. Each class is `covered`, `partial` or `not_evaluated`, with the reason.

| Code | Meaning |
|---|---|
| `0` | Nothing blocking |
| `1` | Gate exceeded (`gates.pr`, default `probable:critical`) |
| `2` | Usage, configuration or consent error |
| `3` | Model, tool canary or calibration error |
| `4` | Incomplete run: report written, not everything evaluated ([ADR 0007](docs/adr/0007-exit-code-incomplete.md), [ADR 0009](docs/adr/0009-scan-and-why-contract.md)) |

An incomplete run never exits `0`, even when the gate also trips.

## Configuration

Layers, later overriding earlier: built-in defaults → org policy (`CREEP_POLICY`, an absolute path; can lock keys and set limits) → user file (`~/.creep/config.yaml`) → project file (`./creep.yaml`) → flags. `--config` replaces the user and project files. Unknown keys are errors; schema: [schema/config.schema.json](schema/config.schema.json).

The project file comes from the repository being scanned, so it is untrusted. It **cannot**:

- choose where code goes or what reads it: `model.contract`, `model.endpoint`, `model.name`, `model.preset`, `model.run`, `model.env`, `egress.allow`, `model.tier` (unused today: the scan takes the tier from calibration; refused so a future forced-tier option cannot come from the repository);
- choose the sandbox (`sandbox.enabled`, `sandbox.runtime`) or the scanners (`scanners.enabled`, not even to remove one);
- choose what creep writes or prints: `report.formats` and `output.format`, so a CI step that uploads `.creep/report.sarif` or reads `report.json` or the terminal output always gets its input;
- loosen a gate or grant consent: `gates.pr` and `gates.nightly` may only get stricter than the stricter of the built-in gate, the policy limit and the gate the layers before it set (policy defaults, the user file), so a repository cannot hand back the built-in gate to an operator who tightened it;
- raise a limit: `budget.max_tokens`, `budget.max_calls`, `model.timeout_seconds`, `model.max_output_bytes` and `calibration.cache_days` may only be lowered.

Any of these is a configuration error (exit `2`) that names the project file and, for a gate or a limit, the layer that set the value it would loosen. A lower limit cannot make a pull request pass with less checked: work skipped for budget, a call refused by the budget and a timed-out model call each make the run incomplete (exit `4`). Removing a scanner would leave a complete run without its classes, so the project file cannot set `scanners.enabled` at all.

### Optional scanners

Enable them in your user config, `--config` or the policy: `scanners: { enabled: [gitleaks, osv-scanner] }`. creep runs an installed scanner only from outside the repository, offline, with fixed arguments and no shell ([ADR 0013](docs/adr/0013-scanner-runner.md)):

- **gitleaks** scans files (not git history) with `--redact`. A root `.gitleaksignore` would hide findings, so creep does not run gitleaks there and the run is incomplete.
- **osv-scanner** runs with `--offline --no-ignore` against a local database in `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` (download it once with `osv-scanner --download-offline-databases`); without one it is not run.
- **semgrep** is detected only; creep ships no local rules ([ADR 0010](docs/adr/0010-optional-scanners-detect-only.md)).

Scanner findings are `probable`. A scanner that fails or times out makes the run incomplete.

## Roadmap

| Version | Scope |
|---|---|
| **v0.1** ✅ | CLI, static analysis (Flask, FastAPI, Express), calibration, planner/reader triage, coverage report, redaction gateway, command presets, optional scanners, signed releases |
| v0.2 | Coverage gaps (#214), redaction hardening (#70), preset policy (#229), sandbox runtime and hardened profile (#21 ✅), PoC verification (#22–#25), `--diff`, baseline, GitHub Action (#26–#29), language kits as data (#217) |
| v0.3 | Read-only MCP mode, YAML recipes, public `creep-bench` |
| v1.0 | Organization policy features, HTML report |

Full list: the [v0.2 milestone](https://github.com/sneakercreepers/creep/milestone/2) and the [Roadmap project](https://github.com/orgs/sneakercreepers/projects/1).

## Scope and responsible use

`creep` only analyses local source code. There is no `--url` option, and there will never be evasion, persistence, lateral movement or mass scanning. If you find a vulnerability in someone else's project, follow their disclosure policy.

## Contributing

Contributions are welcome, especially **false positive** and **false negative** reports, which become test cases. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). AI-assisted contributions are fine: see [AGENTS.md](AGENTS.md). To add or fix a preset, use the *Model preset* issue form ([CONTRIBUTING.md](CONTRIBUTING.md#model-presets)).

## Security

Do not open public issues for vulnerabilities in `creep`. See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
