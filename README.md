<div align="center">

# SneakerCreepers · `creep`

**Find vulnerabilities in your own code with whatever model you have — small or large, local or cloud.**
`creep` measures what your model can actually do, plans around it, sends it only redacted code, and tells you plainly what it did *not* check.

[![Release](https://img.shields.io/github/v/release/sneakercreepers/creep?include_prereleases&sort=semver)](https://github.com/sneakercreepers/creep/releases)
[![v0.3 progress](https://img.shields.io/github/milestones/progress-percent/sneakercreepers/creep/3?label=v0.3)](https://github.com/sneakercreepers/creep/milestone/3)
[![Open issues](https://img.shields.io/github/issues/sneakercreepers/creep)](https://github.com/sneakercreepers/creep/issues)
[![CI](https://github.com/sneakercreepers/creep/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sneakercreepers/creep/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sneakercreepers/creep/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/sneakercreepers/creep/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sneakercreepers/creep/badge)](https://scorecard.dev/viewer/?uri=github.com/sneakercreepers/creep)
[![Go Reference](https://pkg.go.dev/badge/github.com/sneakercreepers/creep.svg)](https://pkg.go.dev/github.com/sneakercreepers/creep)
[![Go version](https://img.shields.io/github/go-mod/go-version/sneakercreepers/creep)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Status](https://img.shields.io/badge/status-v0.2.0%20released-green)

</div>

> [!NOTE]
> **[`v0.3.0`](https://github.com/sneakercreepers/creep/releases/tag/v0.3.0) is the current release** (2026-11-24): every [v0.3 milestone](https://github.com/sneakercreepers/creep/milestone/3) issue is closed and its release pentest and architecture review are fixed (#330). The previous release, [`v0.2.0`](https://github.com/sneakercreepers/creep/releases/tag/v0.2.0), brought language-agnostic analysis, the sandbox with PoC verification, gate per mode, baselines, incremental scans and the GitHub Action.
>
> New in v0.3.0:
>
> - **`creep mcp`**: a read-only MCP server over stdio (`scan` in pr mode, `findings`, `why`) so coding agents can call creep ([ADR 0027](docs/adr/0027-mcp-server.md), wiki guide [Using creep from an agent](https://github.com/sneakercreepers/creep/wiki)).
> - **Recipes**: `creep recipe new|lint|test` and `creep recipe add`, installs pinned by commit in `creep.lock` and verified before `creep scan` loads them ([ADR 0025](docs/adr/0025-recipes.md), [ADR 0028](docs/adr/0028-recipe-install-and-lock.md), wiki guide Writing recipes).
> - **`creep bench`**: a public benchmark with safe twins and an honesty metric, a nightly run on a free local model and a regression gate that blocks releases ([ADR 0030](docs/adr/0030-creep-bench.md), wiki guide Sharing model results).
> - **Build mirror** for the sandbox app build, Podman only ([ADR 0029](docs/adr/0029-build-mirror.md)), and docs-only PRs that skip the heavy CI jobs ([ADR 0018](docs/adr/0018-docs-only-exclusions.md) amendment).

---

## What it does

`creep scan` runs, in order: **calibration** (measures your model per vulnerability class and picks a tier), **discovery** (an inventory by file name and bytes, a lexical tripwire of known sink calls, and the model reading whole redacted source files for entry points and sinks; see [Languages](#languages)), the **planner** (deterministic ranking, no model call), the **reader** (the model reads redacted code slices and answers in a closed schema), in a nightly scan with the sandbox enabled **verification** (the app built offline and a PoC run 5 times against it; see [Sandbox and verification](#sandbox-and-verification)), and the **report**.

**Guarantees** (fixed; no config key can turn them off — except that the `codex` and `gemini` presets can read host files outside redaction, `egress.log` and `egress.allow`; see Limits):

- **Redaction through the gateway.** Every model call goes through one package that redacts secrets from the whole file before fragmenting it, checks consent and the token budget, and only then sends.
- **`egress.log`.** Every request is written and fsynced before a byte is sent, then its result, with a payload file (mode `0600`).
- **The planner never reads code.** It receives only IDs, enums, booleans and bounded numbers, so text in the scanned repository cannot steer it.
- **Honest incompleteness.** Anything not evaluated (a file discovery did not read in full, a batch whose discovery canary the model missed, skipped sink, failed scanner, budget hit, a file name that is not a clean relative path) is listed and the run exits `4`, never `0`.
- **Model output is never executed** on your machine.
- No telemetry; no network except the model endpoints you configure.

**Limits:**

- Languages: any whose files carry an extension or a `#!` interpreter from the list in [Languages](#languages); files with other extensions (plain HTML, shell scripts, SQL, configuration) are not read and not listed. Quality is measured only on the Python and JavaScript test apps; on other languages it is not measured yet ([#35](https://github.com/sneakercreepers/creep/issues/35)), and the model can miss an entry point or sink that the tripwire has no signature for. See [Languages](#languages).
- Discovery sends **whole redacted source files** to your model endpoint (the scan says how many on stderr before the first call; `creep estimate` shows the volume). A file whose numbered lines do not fit one discovery call (8 KiB at tier S, 32 KiB at M, 128 KiB at L, less a small canary file and the line numbers) is listed `too_large`, never split, and makes the run incomplete.
- Redaction masks secrets by their shape and context. It does not mask a token built by concatenation (`"ghp_" + "..."`), a value under 8 bytes that shows up again without its key in a later file, a value found only by its context (a URL password, a key's value) that shows up again without it later in the same file, at any length, a digit-free dotted passphrase that starts with a config receiver (`config.is.sparta`), the first argument of a lookup (`getSecret("...")`), a value on a later line than its key, a bare AWS secret key whose key id only appears in a later file, a token disguised with look-alike or invisible characters outside Unicode category Cf (variation selectors, combining marks, Hangul fillers, the braille blank), or a key id that has a format character inside it and is glued to a word by another one. Zero-width and other format characters inside a token are otherwise handled. Full list: [`internal/redact/doc.go`](internal/redact/doc.go) (Detection limits).
- The `codex` and `gemini` presets can read host files outside redaction and `egress.log` (see [Presets](#presets), [ADR 0015](docs/adr/0015-model-presets.md)).
- Dependency trees: files under `node_modules/<pkg>/`, `venv/` or `.venv/` are listed as `vendor` without being read only when the tree's `package.json` or `pyvenv.cfg` exists with exact case and the repository's git index tracks nothing in the tree. Committed vendor code is read like your own, under whatever name git tracks it. A package installed from a `file:` or git dependency counts as installed. Without a readable `.git/index` at the scan root (a subdirectory or a tarball, a split or sparse index, `index.skipHash`), every vendor file is read, which can make the run incomplete. Go and PHP `vendor/` trees are always read like your own code. A complete run prints how many files it left out by design.
- Links and Windows junctions are never followed. A symbolic link whose relative target names a directory or file creep scans at its own path is not listed: pnpm, npm or yarn workspace links on Linux and macOS, a venv's `lib64 -> lib`. Any other link that could be a directory is listed `not_regular` and makes the run incomplete: an absolute, outside, missing or chained target, a link into the root `.git` or `.creep`, and every Windows junction, so a pnpm or npm workspace tree on Windows, which uses junctions, ends incomplete. Inside an installed dependency tree it is `vendor`. A link to a file is listed only when its name is a source name ([#214](https://github.com/sneakercreepers/creep/issues/214)).

Design and threat model: [docs/design.md](docs/design.md), [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md).

## Languages

Since [#265](https://github.com/sneakercreepers/creep/issues/265) creep has no per-language code ([ADR 0017](docs/adr/0017-language-agnostic-analysis.md)). Every file is classified by an inventory of file names and bytes; every source file is redacted whole, matched against a lexical tripwire of known sink calls, and sent with a few others to your model, which proposes entry points and sinks. The two are combined by union only: the model can add candidates, never remove one or lower its risk, and every candidate is planned at full risk (input-dependent, not parameterized, not authenticated, every HTTP method). Each discovery call carries a synthetic canary file; a reply that misses it is not believed, its files are listed `parse_failed` and the run exits `4`, and the text and Markdown reports name the canary rather than a syntax error. The inventory and the number of whole files sent are in the text and Markdown reports (JSON v1 is unchanged).

What is read:

- **Files read.** Source files with one of these extensions, in any case: `.py`, `.pyw`, `.jinja`, `.jinja2`, `.j2`, `.mako`, `.js`, `.mjs`, `.cjs`, `.jsx`, `.ejs`, `.pug`, `.jade`, `.coffee`, `.ts`, `.mts`, `.cts`, `.tsx`, `.go`, `.php`, `.phtml`, `.inc`, `.php3`, `.php4`, `.php5`, `.php7`, `.php8`, `.phps`, `.twig`, `.java`, `.jsp`, `.jspx`, `.jspf`, `.ftl`, `.xhtml`, `.tag`, `.vm`, `.kt`, `.kts`, `.scala`, `.groovy`, `.gsp`, `.clj`, `.rb`, `.erb`, `.rhtml`, `.haml`, `.slim`, `.rake`, `.ru`, `.cs`, `.cshtml`, `.razor`, `.aspx`, `.ascx`, `.ashx`, `.asmx`, `.asax`, `.master`, `.vb`, `.vbhtml`, `.asp`, `.fs`, `.rs`, `.ex`, `.exs`, `.eex`, `.heex`, `.leex`, `.erl`, `.swift`, `.dart`, `.pl`, `.pm`, `.cgi`, `.psgi`, `.lua`, `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hpp`, `.vue`, `.svelte`, `.cfm`, `.cfc`, `.cfml`, `.hbs`, `.handlebars`, `.mustache`, `.njk`, `.liquid`, `.tpl`. Extensionless files and dotfiles whose `#!` line runs `python`, `pypy`, `node`, `nodejs`, `bun`, `deno`, `ts-node`, `ruby`, `perl` or `php` (directly or through `env`, with any version suffix). A source file over 1 MiB is listed `too_large`; an extensionless file over 1 MiB is judged by its first 8 KiB only.
- **Not read and not listed.** Every other file, so code in it is not scanned and the run can still exit 0. For example: `.html`, `.htm`, `.sh`, `.bash`, `.ps1`, `.sql`, `.yaml`, `.json`, `.xml`, `.toml`, `.ini`, `.hs`, `.ml`, `.jl`, `.r`, `.m`, and `#!/bin/sh` scripts. Manifests and container files (`package.json`, `Dockerfile` and the like) are counted in the inventory, not read. Adding an extension is a one-line data change in [`internal/discover/inventory.txt`](internal/discover/inventory.txt); `TestDocsListInventory` and `TestDocsListShebangs` keep these lists equal to the table.

Limits:

- **Whole-file egress.** Every source file is sent whole, redacted, through the same consent, allowlist, budget and `egress.log`; a consent given before #265 carries over. For sensitive code, use a local model.
- **Quality is not measured on other languages** until [#35](https://github.com/sneakercreepers/creep/issues/35): the tripwire alone finds every expected sink in the test apps, but entry points and sinks it has no signature for depend on the model.
- **Injection** in one file can steer the model for every file in its batch and hide an entry point or sink with no tripwire signature, while still reporting the canary ([threat model R19](docs/threat-model.md)).
- **More incomplete runs at low tiers.** Every candidate ranks at full risk, so runs hit the tier's step cap more often, above all at tier S.
- **Live runs can differ.** Two live runs can propose different candidates; `--record`/`--replay` and the run-state cache keep repeated runs stable.
- Calibration still uses Python and JavaScript tasks, so the tier is measured on those languages.

## Install

### From the GitHub release

Download your archive (linux, darwin, windows · amd64, arm64), `checksums.txt` and `checksums.txt.sigstore.json` from [Releases](https://github.com/sneakercreepers/creep/releases). The current one is [`v0.2.0`](https://github.com/sneakercreepers/creep/releases/tag/v0.2.0).

Verify before running it, with cosign v3+ and the GitHub CLI ([SECURITY.md](SECURITY.md#verifying-a-release)). For `v0.2.0` on linux/amd64:

```sh
cosign verify-blob \
  --certificate-identity 'https://github.com/sneakercreepers/creep/.github/workflows/release.yml@refs/tags/v0.2.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum --check --ignore-missing checksums.txt   # macOS: shasum -a 256 --check --ignore-missing checksums.txt
gh attestation verify creep_0.2.0_linux_amd64.tar.gz \
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
creep reproduce <id>   # run a verified finding's PoC again in the sandbox, offline, without a model
```

Outside CI, the first send to an endpoint asks for your consent; in CI only the org policy's consent list grants it (`creep doctor` prints the consent key).

Guides in the [wiki](https://github.com/sneakercreepers/creep/wiki): [Quickstart](https://github.com/sneakercreepers/creep/wiki/Quickstart), [Sandbox](https://github.com/sneakercreepers/creep/wiki/Sandbox) (what runs where, isolation levels, Podman), [Verification statuses](https://github.com/sneakercreepers/creep/wiki/Verification-statuses), [CI with the Action](https://github.com/sneakercreepers/creep/wiki/CI-with-the-Action), [Nightly scan](https://github.com/sneakercreepers/creep/wiki/Nightly-scan), [Install and verify](https://github.com/sneakercreepers/creep/wiki/Install-and-verify) and [FAQ](https://github.com/sneakercreepers/creep/wiki/FAQ). Where a guide and this README disagree, this README and the ADRs win.

### Presets

A preset sets `contract: command` and a reviewed command line with the CLI's tools switched off. Presets are embedded in the binary ([ADR 0015](docs/adr/0015-model-presets.md)).

| Preset | Command line | Reads host files | Verified with the real CLI |
|---|---|---|---|
| `claude-code` | `claude -p --tools "" --strict-mcp-config --output-format text` | no | yes |
| `gemini` | `gemini --skip-trust --approval-mode default --extensions none --allowed-mcp-server-names creep-no-mcp-server --output-format text`. **API key only**: needs `env: [GEMINI_API_KEY]`; Google AI Pro and Ultra moved to Antigravity CLI, which has no preset (see below) | **yes**: tools, policies and include directories from `~/.gemini/settings.json` | no |
| `codex` (unverified) | `codex exec --sandbox read-only --ignore-user-config -c features.shell_tool=false -c features.view_image=false -c features.apps=false -c features.plugins=false -c features.image_generation=false -c web_search=disabled -c "project_root_markers=[]" --skip-git-repo-check --ephemeral --color never -` | **yes**: shell, image, web and app tools are off (checked with codex-cli 0.171.0, #272), but `apply_patch` cannot be switched off: its host probing tells injected code whether any host file exists and holds a given line (#316); it also reads `~/.codex/AGENTS.md` | no |
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

Behind a corporate proxy, declare the proxy variables in `model.env` as well (`env: [HTTPS_PROXY, NO_PROXY]`): creep never passes them to a model CLI on its own.

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
| `creep accept <id> --expires 90d --reason "..."` | Record a probable or verified finding of the last scan as an accepted risk in `creep-baseline.json` (or `--baseline <file>`); both flags are required, the expiry is 1d to 365d ([ADR 0022](docs/adr/0022-baseline-and-accepted-risks.md)) |
| `creep reproduce <id>` | Run a verified finding's PoC again from its bundle in `.creep/bundles/`, against a fresh offline build, as many times as the scan did; no model is read, configured or called. Needs `sandbox.enabled`. Exit 0 when it verified in at least one run, 1 when in none ([ADR 0020](docs/adr/0020-poc-repetitions-and-bundle.md)) |
| `creep doctor` | Check the model (a command model must pass the tool canary) and the sandbox: runtime, rootless status, isolation level, the pinned images it needs |
| `creep clean` | Remove every container, app image and network creep left on local Docker or Podman, for example after a killed run ([ADR 0016](docs/adr/0016-sandbox-runtime.md)) |
| `creep config explain` | Show each effective config value and its source layer |
| `creep recipe new\|lint\|test <file.json>` | Write a recipe template, check a recipe with no model call, or load it: its vulnerable fixture must be flagged and its safe fixture clean, through the reader and your model. Exit 0 only when it loads, 2 when it is refused, 3 on a model failure ([ADR 0025](docs/adr/0025-recipes.md), schema in [docs/schemas/recipe-v1.json](docs/schemas/recipe-v1.json)) |
| `creep recipe add github.com/<owner>/<repo>@<commit> <clone>` | Install the `recipes/*.json` files of your own git clone of that repository, checked out (detached) at that full 40-hex commit; branch names and tags are refused and creep makes no network call. Files go to `~/.creep/recipes`, pinned by SHA-256 in `creep.lock`. Every `scan` then checks each checksum (a changed file exits 2), the policy's `recipe_sources` allowlist and each recipe's fixtures before giving its hint to the reader ([ADR 0028](docs/adr/0028-recipe-install-and-lock.md)) |
| `creep bench` | Run creep-bench: 12 embedded cases, each a planted vulnerability and its safe twin in Go, Java, JavaScript, PHP, Python or Ruby, kept apart from the calibration templates, through discovery, the planner and the reader at tiers S, M and L. Prints recall, false positives and honesty (of the runs that claimed a class covered, how many found the planted vulnerability) per class, as Markdown or `--format json`. `--replay` reproduces the [published numbers](docs/bench/results.md) from the embedded fixture with no config, state, key or network; without it your model answers through the gateway like a scan (HTTP contracts only), and `--record` also writes the run's fixture. The published fixture is synthesized, so today's numbers measure the pipeline, not a model. Smoke runs on OWASP Juice Shop and PyGoat are not downloaded: scan your own local clone ([ADR 0030](docs/adr/0030-creep-bench.md)) |
| `creep mcp` | Serve the read-only MCP tools `scan` (changed files only), `findings` and `why` over stdio for a coding agent ([MCP server](#mcp-server)) |
| `creep version` | Print version, commit and Go version |

`creep init` and continuing a run with `creep resume` are not implemented yet and fail closed.

### MCP server

`creep mcp` lets a coding agent call creep as an MCP tool over stdio ([ADR 0027](docs/adr/0027-mcp-server.md)). Start it from the repository root in your agent's MCP configuration, for example `{"command": "creep", "args": ["mcp"]}`.

- **Tools.** `scan` takes `changed`, 1 to 1000 repository-relative paths (as `git diff --name-only` prints them), runs a pr-mode scan of only those files (`--changed`) and returns the exit code and the findings; `findings` lists the last report's findings by `status`, a page (`offset`, `limit` up to 200) at a time; `why` returns one finding's evidence by `id`.
- **Read-only.** No tool edits source or applies a fix, writes outside `.creep/`, starts a container, runs a PoC or an optional scanner, or reaches the network: sandbox verification stays CLI-only. The agent is treated as possibly prompt-injected: every argument is bounded and checked, paths outside the repository are refused, and every path and error it gets back is escaped.
- **Before the first call.** Run `creep scan` once from the CLI with the same model: the MCP scan never asks for consent (stdin carries the protocol), never runs a calibration and never creates the state key, so it refuses until those exist. `creep mcp` refuses `--mode nightly`, `--record` and `--recalibrate`.

### Sandbox and verification

The sandbox is optional, and only a nightly scan uses it ([ADR 0021](docs/adr/0021-gate-per-mode.md)). Without a usable runtime, scans run as before and findings stay `probable`.

- **Runtime.** `creep doctor` lists Docker and Podman with their isolation (rootless first, then a Docker Desktop VM, then a rootful daemon, which it warns about). Only a local socket or named pipe is used, never a `tcp://` or `ssh://` endpoint ([ADR 0016](docs/adr/0016-sandbox-runtime.md)).
- **Containers.** Every container runs with no network, no capabilities, a read-only root, user 65534, pids, memory and CPU limits and a timeout, and never mounts the Docker socket or host credentials. The app gets no `.env`: the build context leaves them out.
- **Run network.** PoCs and a synthetic PostgreSQL seeded only from the project's SQL migrations (`migrations/`, `db/migrations/`, Prisma's and a few others) share one `--internal` network per run, `creep-<run>`, with no published port; before each PoC batch a canary container must fail to reach a public IP and to resolve a public name, or the run aborts. Rootful Podman gets no network (its bridge is reachable from the host).
- **Engine versions.** A runtime is usable only with Docker Engine >= 25.0.2 (it embeds BuildKit 0.12.5) whose default runtime is runc >= 1.1.12, or Podman with Buildah >= 1.35.3 and runc >= 1.1.12 or crun >= 1.4.4: older engines let a build escape through links a Dockerfile check cannot see (CVE-2024-21626, CVE-2024-1753, CVE-2024-23652), and crun < 1.4.4 gave containers inheritable capabilities (CVE-2022-27650). creep reads the versions offline from the runtime; a version below a minimum is `old_runtime`, a missing, unparsable or other OCI runtime is `unknown_version`, and either makes the runtime unusable: `creep doctor` names the reason, a scan builds nothing (`no_runtime`) and `creep reproduce` exits `3`. A distribution backport to an older version is refused ([ADR 0016](docs/adr/0016-sandbox-runtime.md)).
- **Images.** creep never pulls images: `creep doctor` lists the two digest-pinned images it needs (BusyBox for the canary and the PoC runner, PostgreSQL) and, for a missing one, the pull command for the endpoint it checked (`docker --host=<endpoint> pull <ref>`, or `podman --remote=false pull <ref>`).
- **App build.** The app image is built only from the repository's own root compose file or `Dockerfile`, never a generated one and never through `docker compose`, and the build is offline: `--network=none`, base images must already be present, no build arguments or secrets, and the build context is a copy without `.env` files, `.git` or credential files. A compose or Dockerfile feature that could escape (privileged or host-network services, host volumes, remote contexts, build secrets, `ADD` of a URL, a `# syntax=` frontend) refuses the build, and any refused or failed build means verification unavailable, never a failed scan.
- **Build mirror.** On rootless Podman, a build that installs packages can reach them through a mirror the operator runs ([ADR 0029](docs/adr/0029-build-mirror.md)): create an internal network (`podman network create --internal --ipv6=false creep-mirror`), attach your registry mirror or allowlisting proxy to it, and set `sandbox.mirror.bridge: creep-mirror` and, for a proxy, `sandbox.mirror.proxy: http://<proxy>:<port>` in the user file, `--config` or policy (never `./creep.yaml`). Before each build creep checks the network is an internal IPv4 bridge and runs the canary on it, which must reach nothing public; RUN steps then join it and get the proxy as `HTTP_PROXY`/`HTTPS_PROXY`. Base images still come only from the local store, every Dockerfile and engine check still applies, and the app never runs on that network. Docker's BuildKit cannot run a build on such a network, so with Docker, rootful Podman or a network that fails a check the build is `mirror_refused` (verification unavailable, never a failed scan). Without these keys the build stays offline.
- **When it runs.** With `sandbox.enabled: true` (user or policy config only; the project file cannot set it) and a usable runtime, a nightly scan (`creep scan --mode nightly`, [CI](#ci-pull-request-and-nightly-scans)) builds the app once, after the analysis and within the scan deadline, from the scan's own file list, and removes the image when it ends; a pr scan never builds it. The report (text, Markdown and SARIF; JSON v1 does not change) says whether the app was built or why verification is unavailable, as a closed reason such as `no_build_file`, `dockerfile_refused`, `base_image_missing`, `build_failed` or `no_runtime`; the build never fails the scan or makes it incomplete, and in a nightly scan a verification that did not run reads the nightly gate at probable.
- **PoCs.** With an app built, the scan asks the model for one PoC per probable `sqli`, `path_traversal` or `template_injection` finding (at most 16), as a closed template creep owns ([ADR 0019](docs/adr/0019-poc-templates.md)), and runs it 5 times in the sandbox, each time with a fresh nonce: 5 of 5 is `verified`, 1 to 4 of 5 `verified` with its rate (`verified in 3/5 runs, intermittent`, in the text, Markdown and SARIF reports; JSON v1 reads `verified`), and 0 of 5 leaves the finding `probable`, since the app is the repository's own and could fail a PoC on purpose. The app must declare its port (`EXPOSE`), or verification is unavailable (`no_port`).
- **Bundles.** Each verified finding gets a reproduction bundle, `.creep/bundles/<id>.json` (the PoC, every request and response, the image IDs, the commit, the database seed's digest and the timings), redacted like everything the scan sends; `creep reproduce <id>` runs it again with no model ([ADR 0020](docs/adr/0020-poc-repetitions-and-bundle.md)).
- **Test apps.** Each app in `testdata/apps` ships one Dockerfile, from the pinned BusyBox, that only copies its files: an offline build cannot install Flask, FastAPI or Express, so the image holds the app but does not serve it; with a build mirror (above) a Dockerfile could install them.

### Flags

| Flag | Effect |
|---|---|
| `--config <path>` | Use this file instead of the user and project files (the policy still applies) |
| `--model-run <cmd>` | Model CLI for the command contract |
| `--mode pr\|nightly` | `scan`: the gate that judges the run; only `nightly` builds the app and runs PoCs (default `pr`, `nightly` on a GitHub Actions `schedule` event; [CI](#ci-pull-request-and-nightly-scans)) |
| `--record` / `--replay` | Record every model response / serve only recorded responses, never the network; `bench` writes its run's fixture / serves its published fixture |
| `--recalibrate` | Calibrate again even if a calibration is cached (30 days) |
| `--stats` | `scan`: print phase times, model calls, cache hits and tokens |
| `--changed <file>` | `scan` and `estimate`: evaluate only the paths listed in the file (see Incremental scans) |
| `--stability <n>` | `scan` and `estimate`: send every discovery batch and hypothesis to the model n times (1 to 5); a probable finding seen in fewer runs is labeled `unstable discovery: seen in 2 of 3 runs` in every report (JSON `stability`), apart from an intermittent PoC; it never lowers a finding or changes the gate, costs about n times the calls (`creep estimate --stability n` shows it), and feeds per-class counts into the calibration line ([ADR 0024](docs/adr/0024-discovery-stability.md)) |
| `--price-in <n>` / `--price-out <n>` | `estimate` and `--stats`: price per 1M input/output tokens, for a cost |
| `--format`, `--log-level` | Output format (`text`, `json`, `sarif`, `markdown`) and log level |
| `--baseline <file>` | `scan`: the gate skips findings a live entry of the file matches, each still listed; `accept`: the file to write |
| `--baseline-write` | `scan`: rewrite `--baseline` from this run's findings (a complete run only); accepted risks are kept, baseline entries expire in 90 days |
| `--expires <n>d`, `--reason <text>` | `accept`: when the accepted risk expires, and why it is accepted |

**Incremental scans.** `--changed <file>` limits a scan to the files a list names, one repository-relative path per line or NUL-separated. creep never runs git and has no `--diff <ref>`, so build the list with git yourself:

```sh
git diff --name-only -z origin/main > changed.txt      # changes since main
git diff --cached --name-only -z > changed.txt         # pre-commit: staged changes
creep scan --changed changed.txt
```

In CI, diff against the event's base commit (`git diff --name-only -z "$BASE_SHA"...HEAD`). Use `-z`: without it git quotes unusual names, and creep refuses a quoted entry, an absolute path, a `..` and a backslash (exit 2). The list only selects among the files the walk finds, so links are still not followed and `.git` and `.creep` are still skipped; deleted files and directories in it are counted and ignored, and names match without regard to case. Every other source file is listed `unchanged`, by design, and counted beside the coverage, and the text summary, Markdown and SARIF mark the run incremental. An incremental exit `0` means the listed files are clean, not the repository: a flow from a changed file into an unchanged one is not evaluated, so keep a full scan (for example nightly) as well ([ADR 0009](docs/adr/0009-scan-and-why-contract.md), #26 amendment).

**Calibration cache.** A calibration is kept in your user cache directory for `calibration.cache_days` (default 30) and reused only for the same contract, endpoint, model name, structured-output mode, max output tokens and retries, and the same creep task set and prompts; changing any of them calibrates again. creep cannot see which snapshot a model name points to: a dated name (`model-2025-06-01`) gets its own entry, but an alias such as `-latest` that the provider moves to a new snapshot keeps its cached tier until the entry expires. Pin a dated model name, or pass `--recalibrate` after the provider updates the alias. The `calibration:` line of `creep scan` shows the tier and, when the context probe stopped early, the size and reason (for example `8 KiB probe: HTTP 400`, which holds the model at tier S). A `calibrations/` cache directory that is a link or junction is refused before any model call, also with `--recalibrate`; the error names the directory to remove.

## Output and exit codes

`creep scan` writes `.creep/report.json` ([schema v1](docs/schemas/report-v1.json)), `.creep/report.sarif` and `.creep/report.md`, per `report.formats`. Reports from earlier runs are removed before each run. Each class is `covered`, `partial` or `not_evaluated`, with the reason. Schema v1 changes additively only; since #26 a not-evaluated file may also have the reason `unchanged` (left out of an incremental scan).

| Code | Meaning |
|---|---|
| `0` | Nothing blocking |
| `1` | Gate exceeded: the gate of the scan's mode, `gates.pr` (default `probable:critical`), or for a nightly scan `gates.nightly` (default `verified:high`, read as `probable:high` when the nightly scan could not verify) and `gates.pr` |
| `2` | Usage, configuration or consent error |
| `3` | Model, tool canary, calibration or sandbox error |
| `4` | Incomplete run: report written, not everything evaluated ([ADR 0007](docs/adr/0007-exit-code-incomplete.md), [ADR 0009](docs/adr/0009-scan-and-why-contract.md)) |

An incomplete run never exits `0`, even when the gate also trips.

**Baseline.** To gate only on new findings, take a baseline from a complete scan, commit it, and pass it to every scan ([ADR 0022](docs/adr/0022-baseline-and-accepted-risks.md)):

```sh
creep scan --baseline creep-baseline.json --baseline-write   # once, from a complete run
creep accept sink-3 --expires 90d --reason "admin-only tool, fix in #12"
creep scan --baseline creep-baseline.json
```

A finding is matched by its fingerprint (class, path and redacted sink line), so lines moving do not make it new; editing the sink line does. Every entry expires (baseline entries after 90 days, accepted risks when you say, at most 365 days), and an expired entry stops suppressing. A suppressed finding is still listed, with its expiry and reason, in the text summary, Markdown, SARIF (`suppressions`) and JSON (`suppression`); only the gate skips it. A not-evaluated finding is never suppressed, and an incomplete run still exits `4`. A malformed baseline, a link in its place or an expiry over a year away exits `2`. In a pull request, read the baseline from the base commit, so the pull request cannot suppress its own finding: `git show "$BASE_SHA:creep-baseline.json" > "$RUNNER_TEMP/baseline.json"` and `creep scan --baseline "$RUNNER_TEMP/baseline.json"`.

## CI: pull request and nightly scans

The scan's mode picks the gate that judges it ([ADR 0021](docs/adr/0021-gate-per-mode.md)):

| Mode | Gate (default) | Sandbox | Chosen by |
|---|---|---|---|
| `pr` | `gates.pr` (`probable:critical`) | never: no build and no PoC, even with `sandbox.enabled`, so it never waits for verified findings | the default |
| `nightly` | `gates.nightly` (`verified:high`) and `gates.pr` | builds the app and runs PoCs when `sandbox.enabled` | `--mode nightly`, or a GitHub Actions `schedule` event |

The mode is never a config key, so the scanned repository cannot pick it; `--mode` always wins. A nightly scan also reads `gates.pr`, so it never passes what a pr scan fails. Each mode reads its keys with the same rules: the policy's `limits.gates.pr` and `limits.gates.nightly` floor both in every mode, and the project file may only make either stricter. A nightly scan that could not verify (`sandbox.enabled` false, verification unavailable for any reason, or a PoC candidate that got no run) reads `gates.nightly` at probable, `verified:high` as `probable:high`, so a finding nothing verified fails the run instead of passing it. Each scan prints its gate on stderr, for example `gate: nightly mode (GitHub Actions schedule event): gates.nightly "verified:high" (default) read as "probable:high": verification unavailable (no_runtime)`, and `creep config explain` ends with the `mode` and `gate` rows. A finding no PoC template can verify (`ssrf`, `command_injection`, `nosql_injection`, scanner findings) is read at probable in every nightly run, since nothing could verify it; accept one with a baseline entry ([ADR 0022](docs/adr/0022-baseline-and-accepted-risks.md)). A PoC that ran and never verified leaves its finding `probable`: `gates.pr` still fails a critical one, but a 0/5 probable high finding passes both default gates; set `gates.nightly: probable:high` in the user file or policy to fail on those too.

A nightly workflow. Everything creep trusts comes from outside the repository: the policy (model, endpoint, consent, sandbox) is written by the workflow, the model key is the only secret and reaches only the scan step, the token is read-only and every action is pinned by SHA. Replace the placeholders, and pull the images `creep doctor` lists first (creep never pulls):

```yaml
# .github/workflows/creep-nightly.yml
name: creep nightly
on:
  schedule:
    - cron: "41 2 * * *"   # a schedule event: nightly mode without a flag
  workflow_dispatch:
permissions: {}
concurrency:
  group: creep-nightly
  cancel-in-progress: false
jobs:
  nightly:
    runs-on: ubuntu-latest
    timeout-minutes: 150
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version: "1.27"
          cache: false
      - name: Install creep
        run: |
          go install github.com/sneakercreepers/creep/cmd/creep@<release tag>
          echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"
      - name: Policy, outside the repository
        run: |
          mkdir -p "$RUNNER_TEMP/creep"
          cat > "$RUNNER_TEMP/creep/policy.yaml" <<'EOF'
          defaults:
            model: { contract: openai, endpoint: "https://<host>/v1", name: "<model>" }
            egress: { allow: ["<host>"] }
            sandbox: { enabled: true }
          consent: ["https://<host>"]   # the endpoint's origin; a command model takes the key creep doctor prints
          EOF
      - name: Sandbox images
        env:
          CREEP_POLICY: ${{ runner.temp }}/creep/policy.yaml
        run: |
          creep doctor
          docker pull "<each image doctor lists as missing, by digest>"
      - name: Nightly scan
        env:
          CREEP_POLICY: ${{ runner.temp }}/creep/policy.yaml
          CREEP_API_KEY: ${{ secrets.CREEP_API_KEY }}
        run: creep scan --mode nightly
```

Exit `1` fails the job when a finding reaches `gates.nightly` or `gates.pr`, `4` when the run is incomplete. The reports are in `.creep/`; upload them with `actions/upload-artifact` (pinned by SHA) if you want them after the run. The pull request workflow is the same without `sandbox` and with `creep scan` (pr mode), on `pull_request`, never `pull_request_target` (which would run the pull request's code with the base repository's secrets). A `pull_request` run uses the pull request's own copy of the workflow, so protect `.github/workflows` with CODEOWNERS and make the scan a required check. The [GitHub Action](#github-action) does the same: on a `schedule` event it runs nightly with no `mode` input, and `mode: nightly` sets `--mode` for any other event.

## GitHub Action

The repository root is a composite Action ([ADR 0023](docs/adr/0023-github-action.md)). Full example: [docs/examples/creep-action.yml](docs/examples/creep-action.yml).

```yaml
permissions:
  contents: read
  security-events: write   # SARIF upload to code scanning
  pull-requests: write     # the pull request comment; not needed with comment: "false"
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    with: { fetch-depth: 2, persist-credentials: false }
  - uses: sneakercreepers/creep@<commit SHA of the release tag> # <release tag>
    env:
      CREEP_POLICY: ${{ runner.temp }}/creep-policy.yaml   # model, endpoint and consent, written by an earlier step
    with:
      version: <release tag>
      api-key: ${{ secrets.CREEP_API_KEY }}
```

- **Verified install.** It downloads the release archive for the runner (Linux or macOS, X64 or ARM64) and runs it only after its SHA-256 matches `checksums.txt` and `gh attestation verify` accepts its build provenance from this repository's release workflow at that tag, built on a GitHub-hosted runner. `version` defaults to the tag the Action is used at; pinned by commit SHA, set it. There is no moving `v0` tag.
- **Forks and events.** It runs on `pull_request`, `push`, `schedule`, `workflow_dispatch` and `merge_group`, and fails on any other event (never use `pull_request_target`). On a pull request from a fork it fails if a model key is set, and otherwise runs without the comment. A fork's pull request gets no key, so the example skips that job and scans the change on push after review.
- **Verdict.** Every exit code but `0` fails the job, and `4` (incomplete) fails exactly like `1`: a pull request whose `creep.yaml` lowers its own budget cannot pass. SARIF upload and the comment still run first.
- **Pull requests.** With `incremental` (default) it scans only the changed files (`--changed`, from the base commit; check out with `fetch-depth: 2`). The `baseline` input (creep v0.2, #27) is read from the base commit on a pull request or a merge group, so the change under review cannot suppress its own finding.
- **Comment and annotations.** One comment, found by a hidden marker and updated in place, holding creep's Markdown report, which escapes every repository and model string. It is found again among the token account's comments: the workflow token's or a personal token's; with a GitHub App token a new comment is posted each run. Annotations come from code scanning, which marks on a pull request only the alerts its SARIF adds; keep `working-directory` at the repository root when uploading. creep emits no fixes yet, so there are no `suggestion` blocks (deferred to the v3 fix stage).
- **Inputs.** `version`, `api-key`, `config` (`--config`), `mode` (`--mode`, creep v0.2), `baseline`, `incremental`, `working-directory`, `upload-sarif`, `comment`, `github-token`; outputs `exit-code`, `sarif`, `report`, `markdown`. `creep-path` exists only for the Action's own self-test (CI job `action`) and runs an unverified binary.

## Configuration

Layers, later overriding earlier: built-in defaults → org policy (`CREEP_POLICY`, an absolute path; can lock keys and set limits) → user file (`~/.creep/config.yaml`) → project file (`./creep.yaml`) → flags. `--config` replaces the user and project files. Unknown keys are errors; schema: [schema/config.schema.json](schema/config.schema.json).

The project file comes from the repository being scanned, so it is untrusted. It **cannot**:

- choose where code goes or what reads it: `model.contract`, `model.endpoint`, `model.name`, `model.preset`, `model.run`, `model.env`, `egress.allow`, `model.tier` (unused today: the scan takes the tier from calibration; refused so a future forced-tier option cannot come from the repository);
- choose the sandbox (`sandbox.enabled`, `sandbox.runtime`, `sandbox.mirror.bridge`, `sandbox.mirror.proxy`) or the scanners (`scanners.enabled`, not even to remove one);
- choose what creep writes or prints: `report.formats` and `output.format`, so a CI step that uploads `.creep/report.sarif` or reads `report.json` or the terminal output always gets its input;
- pick the scan mode: there is no `mode` key in any file, only `--mode` and the CI event;
- loosen a gate or grant consent: `gates.pr` and `gates.nightly` may only get stricter than the stricter of the built-in gate, the policy limit and the gate the layers before it set (policy defaults, the user file), so a repository cannot hand back the built-in gate to an operator who tightened it;
- raise a limit: `budget.max_tokens`, `budget.max_calls`, `budget.max_seconds`, `model.timeout_seconds`, `model.max_output_bytes` and `calibration.cache_days` may only be lowered.

Any of these is a configuration error (exit `2`) that names the project file and, for a gate or a limit, the layer that set the value it would loosen. A lower limit cannot make a pull request pass with less checked: work skipped for budget, a call refused by the budget, a timed-out model call and a scan past its deadline each make the run incomplete (exit `4`).

`budget.max_seconds` (default 7200, 1 to 86400) is the scan deadline. It starts after calibration, which reads no repository text, and covers discovery, redaction and model reads. A crafted file can make redaction take minutes; past the deadline creep stops inside the file it is on, lists that file and every file and sink it did not reach as not evaluated, writes its reports and exits `4` with reason `budget`, so a CI job ends with an incomplete report instead of a runner timeout. Files it never reached are not read. `creep estimate` is bounded the same way and exits `4` with `PARTIAL ESTIMATE` when cut. Removing a scanner would leave a complete run without its classes, so the project file cannot set `scanners.enabled` at all.

### Optional scanners

Enable them in your user config, `--config` or the policy: `scanners: { enabled: [gitleaks, osv-scanner] }`. creep runs an installed scanner only from outside the repository, offline, with fixed arguments and no shell ([ADR 0013](docs/adr/0013-scanner-runner.md)):

- **gitleaks** scans files (not git history) with `--redact`. The scanned repository cannot hide a finding: a root `.gitleaksignore` is not applied (creep scans every root entry on its own, the ignore file included, and says so on stderr and in the report). If a root directory holds its own `.gitleaksignore`, or the root has more than 256 entries, gitleaks is not run and the run is incomplete.
- **osv-scanner** runs with `--offline --no-ignore` against a local database in `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` (download it once with `osv-scanner --download-offline-databases`); without one it is not run. The database must hold every ecosystem the repository's lockfiles use (for example `Go` for `go.mod`, `npm` for `package-lock.json`); if one is missing, osv-scanner is not run and the run is incomplete (`missing_ecosystem_db`).
- **semgrep** is detected only; creep ships no local rules ([ADR 0010](docs/adr/0010-optional-scanners-detect-only.md)).

Scanner findings are `probable`. A scanner that fails or times out makes the run incomplete.

## Roadmap

| Version | Scope |
|---|---|
| **v0.1** ✅ | CLI, static analysis (Flask, FastAPI, Express; replaced in v0.2 by language-agnostic discovery, #265), calibration, planner/reader triage, coverage report, redaction gateway, command presets, optional scanners, signed releases |
| **v0.2** ✅ | Language-agnostic analysis (#265, [ADR 0017](docs/adr/0017-language-agnostic-analysis.md)), coverage gaps (#213, #214), redaction and config hardening (#70, #71, #62, #63, #106, #190), preset policy (#229) and codex flags checked (#272), sandbox runtime and hardened profile (#21) with minimum engine versions (#311), run network, canary and synthetic database (#22), offline app build (#23), PoC verification and `creep reproduce` (#24, #25), incremental scans with `--changed` (#26), baseline and accepted risks (#27, [ADR 0022](docs/adr/0022-baseline-and-accepted-risks.md)), gate per mode and nightly scan (#28, [ADR 0021](docs/adr/0021-gate-per-mode.md)), GitHub Action (#29, [ADR 0023](docs/adr/0023-github-action.md)), guides (#31), discovery stability `--stability N` (#37, [ADR 0024](docs/adr/0024-discovery-stability.md)), gateway hardening (#115, #116), contract goldens (#135), signed commits on `main` (#49, [ADR 0026](docs/adr/0026-signed-commits.md)); release pentest fixed (#307, #308, #311); released as [`v0.2.0`](https://github.com/sneakercreepers/creep/releases/tag/v0.2.0) (2026-11-22) |
| **v0.3** ✅ | Read-only MCP mode `creep mcp` (#32, [ADR 0027](docs/adr/0027-mcp-server.md)), recipes: format, `creep recipe` and pinned installs with `creep.lock` (#33, #34, [ADR 0025](docs/adr/0025-recipes.md), [ADR 0028](docs/adr/0028-recipe-install-and-lock.md)), public `creep bench` with safe twins and an honesty metric (#35, [ADR 0030](docs/adr/0030-creep-bench.md)), nightly bench CI with a regression gate on releases and docs-only CI fast path (#36), registry mirror for the app build (#277, [ADR 0029](docs/adr/0029-build-mirror.md)), wiki guides Writing recipes, Using creep from an agent (MCP) and Sharing model results (#38); release pentest and architecture review fixed (#330); released as [`v0.3.0`](https://github.com/sneakercreepers/creep/releases/tag/v0.3.0) (2026-11-24) |
| v1.0 | Organization policy features, HTML report |

Full list: the [v0.3 milestone](https://github.com/sneakercreepers/creep/milestone/3), the [v0.2 progress page](https://github.com/sneakercreepers/creep/wiki/v0.2-Progress) and the [Roadmap project](https://github.com/orgs/sneakercreepers/projects/1).

## Scope and responsible use

`creep` only analyses local source code. There is no `--url` option, and there will never be evasion, persistence, lateral movement or mass scanning. If you find a vulnerability in someone else's project, follow their disclosure policy.

## Contributing

Contributions are welcome, especially **false positive** and **false negative** reports, which become test cases. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). AI-assisted contributions are fine: see [AGENTS.md](AGENTS.md). Commits on `main` must be signed (SSH or GPG) and carry `Signed-off-by` (`git commit -s`; [ADR 0026](docs/adr/0026-signed-commits.md)). To add or fix a preset, use the *Model preset* issue form ([CONTRIBUTING.md](CONTRIBUTING.md#model-presets)).

## Security

Do not open public issues for vulnerabilities in `creep`. See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
