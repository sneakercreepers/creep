<div align="center">

# SneakerCreepers · `creep`

**Find vulnerabilities in your own code with whatever model you have — small or large, local or cloud.**
`creep` measures what your model can actually do, plans around it, sends it only redacted code, and tells you plainly what it did *not* check.

[![Release](https://img.shields.io/github/v/release/sneakercreepers/creep?include_prereleases&sort=semver)](https://github.com/sneakercreepers/creep/releases)
[![v0.5 progress](https://img.shields.io/github/milestones/progress-percent/sneakercreepers/creep/7?label=v0.5)](https://github.com/sneakercreepers/creep/milestone/7)
[![Open issues](https://img.shields.io/github/issues/sneakercreepers/creep)](https://github.com/sneakercreepers/creep/issues)
[![CI](https://github.com/sneakercreepers/creep/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sneakercreepers/creep/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sneakercreepers/creep/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/sneakercreepers/creep/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sneakercreepers/creep/badge)](https://scorecard.dev/viewer/?uri=github.com/sneakercreepers/creep)
[![Go Reference](https://pkg.go.dev/badge/github.com/sneakercreepers/creep.svg)](https://pkg.go.dev/github.com/sneakercreepers/creep)
[![Go version](https://img.shields.io/github/go-mod/go-version/sneakercreepers/creep)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Status](https://img.shields.io/badge/status-v0.5.1%20released-green)

</div>

> [!NOTE]
> **[`v0.5.1`](https://github.com/sneakercreepers/creep/releases/tag/v0.5.1) is the current release** (2026-11-26): every [v0.5 milestone](https://github.com/sneakercreepers/creep/milestone/7) issue is closed and its release pentest and architecture review are fixed (#349). v0.5.1 fixes the first Homebrew and Scoop publish, which failed for v0.5.0 (#352); use v0.5.1, as `v0.5.0` has no tap or bucket entry. The previous release, [`v0.4.0`](https://github.com/sneakercreepers/creep/releases/tag/v0.4.0), brought `creep init`, `creep resume` and the verified `gemini` preset.
>
> New in v0.5:
>
> - **Homebrew and Scoop**: `brew install sneakercreepers/tap/creep` (macOS and Linux) and `scoop install creep` from the `sneakercreepers` bucket (Windows). The release workflow pins each archive's SHA-256 after verifying the signature and provenance, from a separate job that alone holds the push token and refuses a downgrade ([ADR 0033](docs/adr/0033-package-managers.md)).
> - **`go install` first** in [Install](#install).

---

## What it does

`creep scan` runs, in order: **calibration** (measures your model per vulnerability class, picks a tier and refuses a model that is unfit; see [Unfit models](#unfit-models)), **discovery** (an inventory by file name and bytes, a lexical tripwire of known sink calls, and the model reading whole redacted source files for entry points and sinks; see [Languages](#languages)), the **planner** (deterministic ranking, no model call), the **reader** (the model reads redacted code slices and answers in a closed schema), in a nightly scan with the sandbox enabled **verification** (the app built offline and a PoC run 5 times against it; see [Sandbox and verification](#sandbox-and-verification)), and the **report**.

**Guarantees** (fixed; no config key can turn them off — except that the `codex` and `gemini` presets can read host files outside redaction, `egress.log` and `egress.allow`; see Limits):

- **Redaction through the gateway.** Every model call goes through one package that redacts secrets from the whole file before fragmenting it, checks consent and the token budget, and only then sends.
- **`egress.log`.** Every request is written and fsynced before a byte is sent, then its result, with a payload file (mode `0600`).
- **The planner never reads code.** It receives only IDs, enums, booleans and bounded numbers, so text in the scanned repository cannot steer it.
- **Honest incompleteness.** Anything not evaluated (a file discovery did not read in full, a batch whose discovery canary the model missed, skipped sink, failed scanner, budget hit, a file name that is not a clean relative path) is listed and the run exits `4`, never `0`.
- **Model output is never executed** on your machine.
- No telemetry; no network except the model endpoints you configure.

**Limits:**

**Not looked for.** creep looks for these classes: `sqli`, `nosql_injection`, `command_injection`, `code_injection` (CWE-94), `insecure_deserialization` (CWE-502), `path_traversal`, `ssrf` and `template_injection`, plus the optional scanners' classes. No scan looks for any other class in any language, so a clean report says nothing about them; every report (text, Markdown, SARIF and JSON `coverage.not_looked_for`) lists them beside the coverage ([ADR 0034](docs/adr/0034-classes-not-looked-for.md)). On a C or C++ repository that includes its main bug class, memory safety. The list (kept equal to the reports by `TestReadmeListsNotLookedFor`):

<!-- not-looked-for:start -->
- memory-safety bugs in C, C++ and unsafe Rust, such as buffer overflows, use after free and format strings (`memory_safety`, CWE-119)
- cross-site scripting (`xss`, CWE-79)
- XML external entities (`xxe`, CWE-611)
- cross-site request forgery (`csrf`, CWE-352)
- open redirects (`open_redirect`, CWE-601)
- insecure direct object references (`idor`, CWE-639)
- missing authentication on a route or function (`missing_auth`, CWE-306)
- broken authentication, such as weak session, token or password checks (`broken_auth`, CWE-287)
- prototype pollution (`prototype_pollution`, CWE-1321)
- weak or misused cryptography (`weak_crypto`, CWE-327)
- race conditions (`race_condition`, CWE-362)
- regular-expression denial of service (`redos`, CWE-1333)
- business-logic flaws (`business_logic`, CWE-840)
<!-- not-looked-for:end -->

- Languages: any. Every regular text file is read and sent to discovery, whatever its language or extension, except a short list of known non-code formats (see [Languages](#languages)); a text file creep cannot read in full is listed and the run exits 4, so exit 0 never hides one. Recall rests on model discovery: the tripwire is a best-effort hint with rows for a few languages only, and a language with no row is found by the model alone. Quality is measured only on the Python and JavaScript test apps; on other languages it is not measured on a real model yet: `creep bench` ([#35](https://github.com/sneakercreepers/creep/issues/35)) covers Go, Java, JavaScript, PHP, Python and Ruby, but its published numbers are a live recording of one unfit 1.5B model only (#356). See [Languages](#languages).
- Discovery sends **whole redacted source files** to your model endpoint (the scan says how many on stderr before the first call; `creep estimate` shows the volume). A file whose numbered lines do not fit one discovery call (8 KiB at tier S, 32 KiB at M, 128 KiB at L, less a small canary file and the line numbers) is listed `too_large`, never split, and makes the run incomplete.
- Redaction masks secrets by their shape and context. It does not mask a token built by concatenation (`"ghp_" + "..."`), a value under 8 bytes that shows up again without its key in a later file, a value found only by its context (a URL password, a key's value) that shows up again without it later in the same file, at any length, a digit-free dotted passphrase that starts with a config receiver (`config.is.sparta`), the first argument of a lookup (`getSecret("...")`), a value on a later line than its key, a bare AWS secret key whose key id only appears in a later file, a token disguised with look-alike or invisible characters outside Unicode category Cf (variation selectors, combining marks, Hangul fillers, the braille blank), or a key id that has a format character inside it and is glued to a word by another one. Zero-width and other format characters inside a token are otherwise handled. Full list: [`internal/redact/doc.go`](internal/redact/doc.go) (Detection limits).
- The `codex` and `gemini` presets can read host files outside redaction and `egress.log` (see [Presets](#presets), [ADR 0015](docs/adr/0015-model-presets.md)).
- Dependency trees and build output: a file is listed `vendor` without being read only when the repository's own `.gitignore` files or `.git/info/exclude` ignore it or a directory above it, and the repository's git index tracks nothing in that tree. No directory name counts by itself: committed code, a `vendor/` tree included, is read like your own, and an ignored tree with any committed file is read in full. A file that is untracked but not ignored is your own work and is read. Global git excludes (`core.excludesFile`) are not read. Without a readable `.git/index` at the scan root (a subdirectory or a tarball, a split or sparse index, `index.skipHash`), nothing is vendor and every file is read, which can make the run incomplete. A complete run prints how many files it left out by design.
- Links and Windows junctions are never followed. A symbolic link whose relative target names a directory or file creep scans at its own path is not listed: pnpm, npm or yarn workspace links on Linux and macOS, a venv's `lib64 -> lib`. Any other link that could be a directory is listed `not_regular` and makes the run incomplete: an absolute, outside, missing or chained target, a link into the root `.git` or `.creep`, and every Windows junction, so a pnpm or npm workspace tree on Windows, which uses junctions, ends incomplete. Inside an ignored, untracked tree it is `vendor`. A link to a file is listed unless its name is a text format discovery never opens ([#214](https://github.com/sneakercreepers/creep/issues/214), [#366](https://github.com/sneakercreepers/creep/issues/366)).

Design and threat model: [docs/design.md](docs/design.md), [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md).

## Languages

Since [#265](https://github.com/sneakercreepers/creep/issues/265) creep has no per-language code ([ADR 0017](docs/adr/0017-language-agnostic-analysis.md)), and since [#366](https://github.com/sneakercreepers/creep/issues/366) no per-language data decides what is read. Every text file is redacted whole, matched against a lexical tripwire of known sink calls, and sent with a few others to your model, which proposes entry points and sinks. The two are combined by union only: the model can add candidates, never remove one or lower its risk, and every candidate is planned at full risk (input-dependent, not parameterized, not authenticated, every HTTP method). Recall rests on model discovery, never on a language having tripwire rows: the tripwire only adds candidates where it has a signature. Each discovery call carries a synthetic canary file; a reply that misses it is not believed, its files are listed `parse_failed` and the run exits `4`, and the text and Markdown reports name the canary rather than a syntax error. The inventory (a label per file from its name or `#!` line, shown to the model as a hint and in the reports; a file it does not name is labeled `text`) and the number of whole files sent are in the text and Markdown reports.

Calibration is language-neutral too ([#358](https://github.com/sneakercreepers/creep/issues/358), [ADR 0037](docs/adr/0037-language-neutral-calibration.md)): its 64 tasks are short programs in one minimal pseudocode (input, transform, sink, each vulnerable task with a safe twin), two templates for each class a scan reads. The tier measures what it decides on (keeping the closed schema, usable context, following data from an input to a sink), not knowledge of your repository's languages, so the same model gets the same tier on every repository, and every report says so (`calibration scope:` in the text summary, a line under the Markdown class table, a SARIF note, `coverage.calibration_scope` in JSON v1). Language competence is protected by design instead: union only, the discovery canary in every batch, and exit `4` on anything not read in full; `creep bench` reports quality per language as data and never gates a scan.

What is read:

- **Files read.** Every regular file whose first 8 KiB hold no NUL byte, in any language and under any name or extension, unless the list below names it. A file over 1 MiB, or one that fits no discovery call, is listed `too_large`, and one that cannot be read `read_failed`; both make the run exit 4. Since v0.6 this covers every text file, not only named source, so a large text file (a fixture, a generated listing) a run skipped before can turn exit 0 into exit 4; a larger tier fits more in one call, and committed files are always read. A file with a NUL byte in its first 8 KiB is listed `binary`, by design, only when that head is not UTF-8 or the file is named as a binary format below; text with a NUL (UTF-8, or starting with a UTF-16 byte order mark), labeled or not, is `read_failed`.
- **Not read.** Known non-code formats, matched by lowercased name. Text formats, never opened and listed `not_code` by design: `.svg`, `.md`, `.markdown`, `.rst`, `.adoc`, `.lock`, `.lockb`, `.sum`, `.jsonl`, `.ndjson`, `.geojson`, `.csv`, `.tsv`, `.map`, `.log`, `.pem`, `.crt`, `.cer`, the names `license`, `licence`, `copying`, `notice`, `license.txt`, `licence.txt`, `copying.txt`, `notice.txt`, and the lockfile patterns `*-lock.json`, `*-lock.yaml`, `*.lock.json`. Binary formats, opened and listed `binary` when their first 8 KiB hold a NUL or are not UTF-8 (a text file named like an image is read): `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.ico`, `.icns`, `.webp`, `.avif`, `.heic`, `.tif`, `.tiff`, `.psd`, `.ttf`, `.otf`, `.woff`, `.woff2`, `.eot`, `.mp3`, `.mp4`, `.m4a`, `.wav`, `.ogg`, `.flac`, `.webm`, `.mov`, `.avi`, `.mkv`, `.zip`, `.tar`, `.gz`, `.tgz`, `.bz2`, `.xz`, `.zst`, `.7z`, `.rar`, `.o`, `.a`, `.so`, `.dll`, `.dylib`, `.exe`, `.obj`, `.lib`, `.wasm`, `.bin`, `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.odt`, `.ods`, `.epub`, `.sqlite`, `.sqlite3`, `.db`, `.parquet`, `.avro`, `.npy`, `.npz`. `.json` is config, which may hold a policy or settings a program loads: it is read like code and listed `not_code` only when it does not fit one discovery call. The list is data in [`internal/discover/formats.txt`](internal/discover/formats.txt) and names formats only, never a language; `TestDocsListFormats` keeps this list equal to it. Code in one of these files that a program runs or includes by path is not scanned.

Limits:

- **Whole-file egress.** Every source file is sent whole, redacted, through the same consent, allowlist, budget and `egress.log`; a consent given before #265 carries over. For sensitive code, use a local model.
- **Quality is not measured on other languages** with a real model: `creep bench` ([#35](https://github.com/sneakercreepers/creep/issues/35)) runs six languages, and its published numbers are now a live recording of one weak model only: the nightly bench's digest-pinned `qwen2.5-coder:1.5b` on a CPU runner (2026-11-28, [run](https://github.com/sneakercreepers/creep/actions/runs/46103486289), [#356](https://github.com/sneakercreepers/creep/issues/356)), which calibration finds unfit (`below_chance`, 13 of 64) and places at tier S; with each tier forced it recalls 10 of 12 planted vulnerabilities at every tier but flags 10 or 11 of 12 safe twins, so the numbers say what a model below the fitness floor does, not what a fit one does; the tripwire alone finds every expected sink in the test apps, but in any other language, and for entry points and sinks it has no signature for, findings depend on the model.
- **More files are sent.** Since #366 configuration, container files, scripts and markup are read too: on `testdata/apps` the bytes sent grow from about 16.5 KB to 23.6 KB (about 4,100 to 5,900 tokens, +43%), mostly `requirements.txt`, `Dockerfile` and `compose.yaml`; `creep estimate` measures the same read, and a large text file (over about 7.5 KiB at tier S) now makes a run incomplete.
- **Injection** in one file can steer the model for every file in its batch and hide an entry point or sink with no tripwire signature, while still reporting the canary ([threat model R19](docs/threat-model.md)).
- **More incomplete runs at low tiers.** Every candidate ranks at full risk, so runs hit the tier's step cap more often, above all at tier S.
- **Live runs can differ.** Two live runs can propose different candidates; `--record`/`--replay` and the run-state cache keep repeated runs stable.
- **Calibration costs time before the first finding.** Measured on `qwen2.5-coder:1.5b` with Ollama on a 4-core laptop CPU, no GPU ([#367](https://github.com/sneakercreepers/creep/issues/367)), with the earlier 100-task set: 20 min 18 s, 108 calls, about 50k tokens in, about 11 s per call; the bench job on a GitHub-hosted runner measured 107 calls, 51,007 tokens in, 2,151 out and 497 s for the same model, which the fitness floor finds unfit. The neutral set ([#358](https://github.com/sneakercreepers/creep/issues/358)) sends 64 task calls instead of 100 (70 calls with the probes instead of 106, plus retries) and about as many task-call bytes (2% fewer: the task prompt now defines every builtin), so expect about a third less time on a local model, where calls dominate. A hosted model takes seconds per call. The result is cached for 30 days; `--stats` prints what calibration spent and the nightly bench publishes it for the pinned model (`calibration` in its results).

## Install

### With Go (quickest)

Needs Go 1.25 or later:

```sh
go install github.com/sneakercreepers/creep/cmd/creep@latest
```

This builds from source through the Go module proxy and checksum database, so there is no cosign signature or attestation to check; for a verified binary use the release archive below. Or from a clone: `git clone https://github.com/sneakercreepers/creep && cd creep && make build`. Homebrew and Scoop: see [With Homebrew or Scoop](#with-homebrew-or-scoop).

### From the GitHub release

Download your archive (linux, darwin, windows · amd64, arm64), `checksums.txt` and `checksums.txt.sigstore.json` from [Releases](https://github.com/sneakercreepers/creep/releases). The current one is [`v0.5.1`](https://github.com/sneakercreepers/creep/releases/tag/v0.5.1).

Verify before running it, with cosign v3+ and the GitHub CLI ([SECURITY.md](SECURITY.md#verifying-a-release)). For `v0.5.1` on linux/amd64:

```sh
cosign verify-blob \
  --certificate-identity 'https://github.com/sneakercreepers/creep/.github/workflows/release.yml@refs/tags/v0.5.1' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum --check --ignore-missing checksums.txt   # macOS: shasum -a 256 --check --ignore-missing checksums.txt
gh attestation verify creep_0.5.1_linux_amd64.tar.gz \
  --repo sneakercreepers/creep \
  --signer-workflow sneakercreepers/creep/.github/workflows/release.yml
```

A certificate or attestation naming any other workflow, ref or repository means the file was not built by the release workflow: do not run it. Each archive also ships an SPDX SBOM (`<archive>.sbom.json`).

### With Homebrew or Scoop

The release workflow also publishes a Homebrew cask (macOS and Linux, amd64 and arm64) and a Scoop manifest (Windows, amd64 and arm64):

```sh
brew install sneakercreepers/tap/creep

scoop bucket add sneakercreepers https://github.com/sneakercreepers/scoop-bucket
scoop install creep
```

Both install the release archive above and check only its SHA-256, which the release workflow pinned after verifying the signature and provenance. brew and scoop do not check the cosign signature or the attestation themselves, so for that assurance still run the commands above on the archive they downloaded (`brew --cache --cask sneakercreepers/tap/creep`, or `scoop cache show creep`) ([ADR 0033](docs/adr/0033-package-managers.md)).

## Quick start

Put the model in **your** config (`~/.creep/config.yaml`, `--config` or the org policy), never in the repository's `creep.yaml`:

```yaml
# ~/.creep/config.yaml
model: { preset: claude-code }
```

Then, from the repository root:

```sh
creep config explain   # every effective value and the layer it came from
creep doctor           # runs the tool canary, probes the model with synthetic calls and reports the sandbox runtime
creep estimate         # calls, tokens and time of a scan, without calling a model
creep scan             # scans the current directory; reports in .creep/
creep why <id>         # the evidence behind one finding of the last scan
creep reproduce <id>   # run a verified finding's PoC again in the sandbox, offline, without a model
```

Outside CI, the first send to an endpoint asks for your consent; in CI only the org policy's consent list grants it (`creep doctor` prints the consent key).

Guides in the [wiki](https://github.com/sneakercreepers/creep/wiki): [Quickstart](https://github.com/sneakercreepers/creep/wiki/Quickstart), [Sandbox](https://github.com/sneakercreepers/creep/wiki/Sandbox) (what runs where, isolation levels, Podman), [Verification statuses](https://github.com/sneakercreepers/creep/wiki/Verification-statuses), [CI with the Action](https://github.com/sneakercreepers/creep/wiki/CI-with-the-Action), [Nightly scan](https://github.com/sneakercreepers/creep/wiki/Nightly-scan), [Install and verify](https://github.com/sneakercreepers/creep/wiki/Install-and-verify), [Writing recipes](https://github.com/sneakercreepers/creep/wiki/Writing-recipes), [Using creep from an agent](https://github.com/sneakercreepers/creep/wiki/Using-creep-from-an-agent), [Sharing model results](https://github.com/sneakercreepers/creep/wiki/Sharing-model-results) and [FAQ](https://github.com/sneakercreepers/creep/wiki/FAQ). Where a guide and this README disagree, this README and the ADRs win.

### Presets

A preset sets `contract: command` and a reviewed command line with the CLI's tools switched off. Presets are embedded in the binary ([ADR 0015](docs/adr/0015-model-presets.md)).

| Preset | Command line | Reads host files | Verified with the real CLI |
|---|---|---|---|
| `claude-code` | `claude -p --tools "" --strict-mcp-config --output-format text` | no | yes |
| `gemini` | `gemini --skip-trust --approval-mode default --extensions none --allowed-mcp-server-names creep-no-mcp-server --output-format text`. **API key only**: needs `env: [GEMINI_API_KEY]`; verified with `env: [GEMINI_API_KEY, GEMINI_CLI_HOME, GEMINI_MODEL]`, an empty `GEMINI_CLI_HOME` whose `.gemini/settings.json` only selects `gemini-api-key` (recommended: the user settings, tools, policies and MCP servers then do not load) and `GEMINI_MODEL=gemini-3.5-flash-lite` on the free tier; a Google account login fails headless ("This client is no longer supported for Gemini Code Assist for individuals", Gemini CLI 0.70.0 and 0.71.1, #333) and with `security.auth.selectedType: oauth-personal` in `~/.gemini/settings.json` the key is ignored: switch it to `gemini-api-key` (`/auth`); Google AI Pro and Ultra moved to Antigravity CLI, which has no preset (see below) | **yes**: tools, policies and include directories from `~/.gemini/settings.json` | yes (Gemini CLI 0.70.0, AI Studio key, #338), only with `GEMINI_CLI_HOME` in `env`: without it every scan warns that the preset is not verified for the run |
| `codex` (unverified) | `codex exec --sandbox read-only --ignore-user-config -c features.shell_tool=false -c features.view_image=false -c features.apps=false -c features.plugins=false -c features.image_generation=false -c web_search=disabled -c "project_root_markers=[]" --skip-git-repo-check --ephemeral --color never -` | **yes**: shell, image, web and app tools are off (checked with codex-cli 0.171.0, #272, and again with `codex features list` in #333), but `apply_patch` cannot be switched off: its host probing tells injected code whether any host file exists and holds a given line (#316); it also reads `~/.codex/AGENTS.md`. Works with a ChatGPT login and passes the tool canary, but on Windows the tools-on control passes too, so it stays unverified (#333) | no |
| `ollama` | `ollama run <model.name> --format json` (needs `name: <model>`) | no | no |

> [!WARNING]
> The tool canary catches writes and commands, not reads. With `gemini` or `codex`, scanned code could steer the CLI to read host secrets (`~/.ssh`, `~/.aws`) and send them to its provider **unredacted, outside `egress.log`**. `gemini` denies `web_fetch` in headless mode and sends `google_web_search` queries to Google, its provider, but a tool or policy your `~/.gemini/settings.json` allows could reach any address outside `egress.allow`. This is an accepted residual risk (ADR 0015, threat model C6, [#229](https://github.com/sneakercreepers/creep/issues/229)): creep only warns at `creep doctor` and every scan, as it does for unverified presets. Do not use them on untrusted code or on a machine whose home directory holds secrets; prefer `claude-code` or `ollama`.

The `gemini` preset needs a Google AI Studio key: a personal Google login fails in headless mode ("This client is no longer supported for Gemini Code Assist for individuals"). Declare the key in `model.env` so it reaches the CLI (creep passes only a minimal environment plus `model.env`):

```yaml
# ~/.creep/config.yaml
model:
  preset: gemini
  env: [GEMINI_API_KEY, GEMINI_CLI_HOME]   # GEMINI_CLI_HOME: an isolated home whose .gemini/settings.json selects gemini-api-key (CONTRIBUTING.md, Model presets)
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

**Local models (Ollama).** Point the `openai` contract at `http://127.0.0.1:11434/v1` (or use the `ollama` preset) and give the model a context window large enough for creep's calls. Ollama's default `num_ctx` is far smaller than a discovery call (about 11 KiB at tier S, 36 KiB at M, 133 KiB at L, plus the reply), and Ollama cuts a longer input silently, system prompt first. Create the model with `num_ctx` 16384 or more, as the nightly bench does:

```sh
printf 'FROM qwen2.5-coder:7b
PARAMETER num_ctx 16384
PARAMETER temperature 0
' > Modelfile
ollama create creep-qwen -f Modelfile   # then model.name: creep-qwen
```

`creep doctor` sends the model two synthetic probes that hold no repository text, through the gateway (consent, budget and `egress.log` apply): a discovery batch of only creep's canary, and a context probe the size of the tier's largest discovery call. It warns when the reply breaks the schema or misses the canary, or when the usable context is below what the tier needs; the tier is the cached calibration's, or S before the first scan ([ADR 0035](docs/adr/0035-doctor-model-probes.md)).

Which replay fixtures are live ([#356](https://github.com/sneakercreepers/creep/issues/356), [ADR 0038](docs/adr/0038-live-replay-fixtures.md)): the reader's tier-S replies, the small-model discovery batch (`internal/discover/testdata/replay/live-s`), one calibration (`internal/calibrate/testdata/replay/live_seed1.json`) and the published bench fixture were recorded on 2026-11-28 from the pinned `qwen2.5-coder:1.5b` ([run](https://github.com/sneakercreepers/creep/actions/runs/46103486289)); each has a header naming the model, digest, date and the outcomes it replays to. The reader's tier-M and tier-L replies and the three seed-1 calibration fixtures are still **synthesized** from ground truth, and say so in their headers: this model is unfit and calibrates at S, so it cannot stand in for a model that calibrates at M or L.

Your own CLI also works with `contract: command` and `run:` (prompt on stdin, JSON on stdout), or `--model-run <cmd>`. It runs only through the gateway: no shell, an empty private directory under the user cache directory, a minimal environment, a timeout and an output cap ([ADR 0014](docs/adr/0014-command-model-through-gateway.md)).

## Commands and flags

| Command | What it does |
|---|---|
| `creep init` | Write `./creep.yaml` with every setting the project file may hold outside `model.*` (gates, budget limits, calibration cache, log level), each commented out at its built-in default with a one-line why, so the file changes nothing until edited; prints where the model and the other operator-only settings go. An existing `creep.yaml`, or a link, directory or FIFO at that path, is refused with exit 2 and never overwritten; no model call, no network ([ADR 0031](docs/adr/0031-creep-init.md)) |
| `creep scan` | Scan the current directory; write `.creep/report.*` |
| `creep estimate` | Build every request a scan would send and measure it; no model call, no network ([ADR 0011](docs/adr/0011-estimate-and-stats.md)) |
| `creep why <id>` | Show the evidence behind a finding of the last scan |
| `creep accept <id> --expires 90d --reason "..."` | Record a probable or verified finding of the last scan as an accepted risk in `creep-baseline.json` (or `--baseline <file>`); both flags are required, the expiry is 1d to 365d ([ADR 0022](docs/adr/0022-baseline-and-accepted-risks.md)) |
| `creep reproduce <id>` | Run a verified finding's PoC again from its bundle in `.creep/bundles/`, against a fresh offline build, as many times as the scan did; no model is read, configured or called. Needs `sandbox.enabled`. Exit 0 when it verified in at least one run, 1 when in none ([ADR 0020](docs/adr/0020-poc-repetitions-and-bundle.md)) |
| `creep doctor` | Check the model and the sandbox. A command model must pass the tool canary; every model then gets two synthetic probes through the gateway (a discovery batch of only the canary, a context probe the size of the tier's discovery call), with a warning, exit 0, when the reply breaks the schema, misses the canary or the context is too small (for Ollama, raise `num_ctx`), and exit 3 when the model cannot be reached ([ADR 0035](docs/adr/0035-doctor-model-probes.md)). Sandbox: runtime, rootless status, isolation level, the pinned images it needs |
| `creep clean` | Remove every container, app image and network creep left on local Docker or Podman, for example after a killed run ([ADR 0016](docs/adr/0016-sandbox-runtime.md)) |
| `creep resume <run>` | Continue a scan that stopped before writing its report (killed, or a calibration failure), with the same config and flags; the run ID is its folder in `.creep/runs/`. A changed config, model, `model.env` value, contract, endpoint, tier, mode, creep version, prompt, file, baseline, `--changed` list, `--stability`, `--recalibrate` or installed recipe is refused with exit 2 and nothing sent; live, `--record` or `--replay` comes from the run. Finished calls are served from `.creep/cache` and never sent again; the call that was cut is sent again, and `egress.log` lists both attempts. The budget and `budget.max_seconds` keep counting what the run already spent ([ADR 0032](docs/adr/0032-resume.md)) |
| `creep config explain` | Show each effective config value and its source layer |
| `creep recipe new\|lint\|test <file.json>` | Write a recipe template, check a recipe with no model call, or load it: its vulnerable fixture must be flagged and its safe fixture clean, through the reader and your model. Exit 0 only when it loads, 2 when it is refused, 3 on a model failure ([ADR 0025](docs/adr/0025-recipes.md), schema in [docs/schemas/recipe-v1.json](docs/schemas/recipe-v1.json)). `class` is one of `sql_injection`, `command_injection`, `path_traversal`, `ssrf`, `template_injection`, `nosql_injection`, `code_injection` or `insecure_deserialization`; since [ADR 0034](docs/adr/0034-classes-not-looked-for.md) findings at an eval or deserialization sink carry the last two, so `lint`, and `scan` for each installed recipe, warn when a `command_injection` recipe's vulnerable fixture has such a sink (or a recipe of those two classes has only a shell sink, or the other one's) and name the class to set; the recipe still loads (#371) |
| `creep recipe add github.com/<owner>/<repo>@<commit> <clone>` | Install the `recipes/*.json` files of your own git clone of that repository, checked out (detached) at that full 40-hex commit; branch names and tags are refused and creep makes no network call. Files go to `~/.creep/recipes`, pinned by SHA-256 in `creep.lock`. Every `scan` then checks each checksum (a changed file exits 2), the policy's `recipe_sources` allowlist and each recipe's fixtures before giving its hint to the reader ([ADR 0028](docs/adr/0028-recipe-install-and-lock.md)) |
| `creep bench` | Run creep-bench: 12 embedded cases, each a planted vulnerability and its safe twin in Go, Java, JavaScript, PHP, Python or Ruby, kept apart from the calibration templates, through discovery, the planner and the reader at tiers S, M and L. Prints recall, false positives and honesty (of the runs that claimed a class covered, how many found the planted vulnerability) per class, as Markdown or `--format json`. `--replay` reproduces the [published numbers](docs/bench/results.md) from the embedded fixture with no config, state, key or network; without it your model answers through the gateway like a scan (HTTP contracts only), and `--record` also writes the run's fixture. The published fixture is a live recording of the pinned `qwen2.5-coder:1.5b` (unfit by ADR 0036), so today's numbers are that weak model's, not a fit one's ([ADR 0038](docs/adr/0038-live-replay-fixtures.md)). Smoke runs on OWASP Juice Shop and PyGoat are not downloaded: scan your own local clone ([ADR 0030](docs/adr/0030-creep-bench.md)) |
| `creep mcp` | Serve the read-only MCP tools `scan` (changed files only), `findings` and `why` over stdio for a coding agent ([MCP server](#mcp-server)) |
| `creep version` | Print version, commit and Go version |


### MCP server

`creep mcp` lets a coding agent call creep as an MCP tool over stdio ([ADR 0027](docs/adr/0027-mcp-server.md)). Start it from the repository root in your agent's MCP configuration, for example `{"command": "creep", "args": ["mcp"]}`.

- **Tools.** `scan` takes `changed`, 1 to 1000 repository-relative paths (as `git diff --name-only` prints them), runs a pr-mode scan of only those files (`--changed`) and returns the exit code and the findings; `findings` lists the last report's findings by `status`, a page (`offset`, `limit` up to 200) at a time; `why` returns one finding's evidence by `id`.
- **Read-only.** No tool edits source or applies a fix, writes outside `.creep/`, starts a container, runs a PoC or an optional scanner, or reaches the network: sandbox verification stays CLI-only. The agent is treated as possibly prompt-injected: every argument is bounded and checked, paths outside the repository are refused, and every path and error it gets back is escaped.
- **Before the first call.** Run `creep scan` once from the CLI with the same model: the MCP scan never asks for consent (stdin carries the protocol), never runs a calibration and never creates the state key, so it refuses until those exist. `creep mcp` refuses `--mode nightly`, `--record` and `--recalibrate`.

### Sandbox and verification

The sandbox is optional, and only a nightly scan uses it ([ADR 0021](docs/adr/0021-gate-per-mode.md)). Without a usable runtime, scans run as before and findings stay `probable`.

- **Runtime.** `creep doctor` lists Docker and Podman with their isolation (rootless first, then a Docker Desktop VM, then a rootful daemon, which it warns about). Only a local socket or named pipe is used, never a `tcp://` or `ssh://` endpoint ([ADR 0016](docs/adr/0016-sandbox-runtime.md)).
- **Containers.** Every container runs with no network, no capabilities, a read-only root, user 65534, pids, memory and CPU limits and a timeout, and never mounts the Docker socket or host credentials. The repository's `.env` never reaches a container (the build context leaves them out); the app gets only creep's synthetic database settings (`DATABASE_URL`, `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`), as environment variables and as a read-only `.env` in its working directory.
- **Run network.** PoCs and a synthetic PostgreSQL that starts empty share one `--internal` network per run, `creep-<run>`, with no published port; before each PoC batch a canary container must fail to reach a public IP and to resolve a public name, or the run aborts. Rootful Podman gets no network (its bridge is reachable from the host).
- **Engine versions.** A runtime is usable only with Docker Engine >= 25.0.2 (it embeds BuildKit 0.12.5) whose default runtime is runc >= 1.1.12, or Podman with Buildah >= 1.35.3 and runc >= 1.1.12 or crun >= 1.4.4: older engines let a build escape through links a Dockerfile check cannot see (CVE-2024-21626, CVE-2024-1753, CVE-2024-23652), and crun < 1.4.4 gave containers inheritable capabilities (CVE-2022-27650). creep reads the versions offline from the runtime; a version below a minimum is `old_runtime`, a missing, unparsable or other OCI runtime is `unknown_version`, and either makes the runtime unusable: `creep doctor` names the reason, a scan builds nothing (`no_runtime`) and `creep reproduce` exits `3`. A distribution backport to an older version is refused ([ADR 0016](docs/adr/0016-sandbox-runtime.md)).
- **Images.** creep never pulls images: `creep doctor` lists the two digest-pinned images it needs (BusyBox for the canary and the PoC runner, PostgreSQL) and, for a missing one, the pull command for the endpoint it checked (`docker --host=<endpoint> pull <ref>`, or `podman --remote=false pull <ref>`).
- **App build.** The app image is built only from the repository's own root compose file or `Dockerfile`, never a generated one and never through `docker compose`, and the build is offline: `--network=none`, base images must already be present, no build arguments or secrets, and the build context is a copy without `.env` files, `.git` or credential files. A compose or Dockerfile feature that could escape (privileged or host-network services, host volumes, remote contexts, build secrets, `ADD` of a URL, a `# syntax=` frontend) refuses the build, and any refused or failed build means verification unavailable, never a failed scan.
- **Build mirror.** On rootless Podman, a build that installs packages can reach them through a mirror the operator runs ([ADR 0029](docs/adr/0029-build-mirror.md)): create an internal network (`podman network create --internal --ipv6=false creep-mirror`), attach your registry mirror or allowlisting proxy to it, and set `sandbox.mirror.bridge: creep-mirror` and, for a proxy, `sandbox.mirror.proxy: http://<proxy>:<port>` in the user file, `--config` or policy (never `./creep.yaml`). Before each build creep checks the network is an internal IPv4 bridge and runs the canary on it, which must reach nothing public; RUN steps then join it and get the proxy as `HTTP_PROXY`/`HTTPS_PROXY`. Base images still come only from the local store, every Dockerfile and engine check still applies, and the app never runs on that network. Docker's BuildKit cannot run a build on such a network, so with Docker, rootful Podman or a network that fails a check the build is `mirror_refused` (verification unavailable, never a failed scan). Without these keys the build stays offline.
- **When it runs.** With `sandbox.enabled: true` (user or policy config only; the project file cannot set it) and a usable runtime, a nightly scan (`creep scan --mode nightly`, [CI](#ci-pull-request-and-nightly-scans)) builds the app once, after the analysis and within the scan deadline, from the scan's own file list, and removes the image when it ends; a pr scan never builds it. The report (text, Markdown and SARIF; JSON v1 does not change) says whether the app was built or why verification is unavailable, as a closed reason such as `no_build_file`, `dockerfile_refused`, `base_image_missing`, `build_failed` or `no_runtime`; the build never fails the scan or makes it incomplete, and in a nightly scan a verification that did not run reads the nightly gate at probable.
- **PoCs.** With an app built, the scan asks the model for one PoC per probable `sqli`, `path_traversal` or `template_injection` finding (at most 16), as a closed template creep owns ([ADR 0019](docs/adr/0019-poc-templates.md)), and runs it 5 times in the sandbox, each time with a fresh nonce: 5 of 5 is `verified`, 1 to 4 of 5 `verified` with its rate (`verified in 3/5 runs, intermittent`, in the text, Markdown and SARIF reports; JSON v1 reads `verified`), and 0 of 5 leaves the finding `probable`, since the app is the repository's own and could fail a PoC on purpose. The app must declare its port (`EXPOSE`), or verification is unavailable (`no_port`).
- **Schema.** The app sets up its own schema: when the root compose file has a `migrate` service with a `command` list (`command: ["python", "migrate.py"]`, `["alembic", "upgrade", "head"]`, `["npx", "knex", "migrate:latest"]`), creep runs that command once in the app image it built, inside the sandbox with the same hardening, after the database is ready and before the app starts; nothing of that service but its command is read. A string `command`, an `entrypoint`, `extends` or no `command` skips only that step, with the reason printed (`string_command`, `entrypoint`, `extends`, `no_command`). Otherwise the app must create its schema when it starts. **Changed in #364:** `.sql` files in `migrations/`, `db/migrations/`, Prisma's and the other fixed folders no longer seed the database by themselves; apply them from the `migrate` command (a framework's migrate tool, or `["psql", "-f", "migrations/001_init.sql"]` when the image ships psql; it reads the `PG*` variables creep sets), or findings that need those tables stay `probable`.
- **Bundles.** Each verified finding gets a reproduction bundle, `.creep/bundles/<id>.json` (the PoC, every request and response, the image IDs, the commit, the migrate command's digest and the timings), redacted like everything the scan sends; `creep reproduce <id>` runs it again with no model ([ADR 0020](docs/adr/0020-poc-repetitions-and-bundle.md)).
- **Test apps.** Each app in `testdata/apps` ships one Dockerfile, from the pinned BusyBox, that only copies its files, except `flaskpg`: a Flask app on a digest-pinned Python image that installs its committed wheels offline and runs its own migrate step. Its committed wheels are for linux/amd64 (CPython 3.13), so it builds only on an amd64 engine. The `Live verify` workflow scans it nightly with the sandbox and fails unless its SQL injection and path traversal are verified 5 of 5 and nothing is verified on its safe twin. Its model answers are synthesized in the test (the reader's claims and the PoCs of the committed PoC fixtures), not replies recorded from a live model: #356 recorded the reader and discovery live at tier S, but this workflow's verification path still runs on synthesized answers.

### Flags

| Flag | Effect |
|---|---|
| `--config <path>` | Use this file instead of the user and project files (the policy still applies) |
| `--model-run <cmd>` | Model CLI for the command contract |
| `--mode pr\|nightly` | `scan`: the gate that judges the run; only `nightly` builds the app and runs PoCs (default `pr`, `nightly` on a GitHub Actions `schedule` event; [CI](#ci-pull-request-and-nightly-scans)) |
| `--record` / `--replay` | Record every model response / serve only recorded responses, never the network; `bench` writes its run's fixture / serves its published fixture |
| `--recalibrate` | Calibrate again even if a calibration is cached (30 days); `bench` (live only): also run one calibration first and add its calls, tokens and time to the results |
| `--allow-unfit-model` | `scan` and `resume`: scan with a model calibration found unfit instead of exiting `3`; every model finding is labeled `unreliable_model` (see [Unfit models](#unfit-models)) |
| `--stats` | `scan`: print phase times, model calls, cache hits and tokens, and calibration's own calls, tokens and time |
| `--changed <file>` | `scan`, `estimate` and `resume`: evaluate only the paths listed in the file (see Incremental scans) |
| `--stability <n>` | `scan`, `estimate` and `resume`: send every discovery batch and hypothesis to the model n times (1 to 5); a probable finding seen in fewer runs is labeled `unstable discovery: seen in 2 of 3 runs` in every report (JSON `stability`), apart from an intermittent PoC; it never lowers a finding or changes the gate, costs about n times the calls (`creep estimate --stability n` shows it), and feeds per-class counts into the calibration line ([ADR 0024](docs/adr/0024-discovery-stability.md)) |
| `--price-in <n>` / `--price-out <n>` | `estimate` and `--stats`: price per 1M input/output tokens, for a cost |
| `--format`, `--log-level` | Output format (`text`, `json`, `sarif`, `markdown`) and log level |
| `--baseline <file>` | `scan` and `resume`: the gate skips findings a live entry of the file matches, each still listed; `accept`: the file to write |
| `--baseline-write` | `scan` and `resume`: rewrite `--baseline` from this run's findings (a complete run only); accepted risks are kept, baseline entries expire in 90 days |
| `--expires <n>d`, `--reason <text>` | `accept`: when the accepted risk expires, and why it is accepted |

**Incremental scans.** `--changed <file>` limits a scan to the files a list names, one repository-relative path per line or NUL-separated. creep never runs git and has no `--diff <ref>`, so build the list with git yourself:

```sh
git diff --name-only -z origin/main > changed.txt      # changes since main
git diff --cached --name-only -z > changed.txt         # pre-commit: staged changes
creep scan --changed changed.txt
```

In CI, diff against the event's base commit (`git diff --name-only -z "$BASE_SHA"...HEAD`). Use `-z`: without it git quotes unusual names, and creep refuses a quoted entry, an absolute path, a `..` and a backslash (exit 2). The list only selects among the files the walk finds, so links are still not followed and `.git` and `.creep` are still skipped; deleted files and directories in it are counted and ignored, and names match without regard to case. Every other source file is listed `unchanged`, by design, and counted beside the coverage, and the text summary, Markdown and SARIF mark the run incremental. An incremental exit `0` means the listed files are clean, not the repository: a flow from a changed file into an unchanged one is not evaluated, so keep a full scan (for example nightly) as well ([ADR 0009](docs/adr/0009-scan-and-why-contract.md), #26 amendment).

**Calibration cache.** A calibration is kept in your user cache directory for `calibration.cache_days` (default 30) and reused only for the same contract, endpoint, model name, structured-output mode, max output tokens and retries, and the same creep task set and prompts; changing any of them calibrates again. creep cannot see which snapshot a model name points to: a dated name (`model-2025-06-01`) gets its own entry, but an alias such as `-latest` that the provider moves to a new snapshot keeps its cached tier until the entry expires. Pin a dated model name, or pass `--recalibrate` after the provider updates the alias. The `calibration:` line of `creep scan` shows the tier and, when the context probe stopped early, the size and reason (for example `8 KiB probe: HTTP 400`, which holds the model at tier S). A `calibrations/` cache directory that is a link or junction is refused before any model call, also with `--recalibrate`; the error names the directory to remove.

### Unfit models

After calibration creep checks a fitness floor over the classes the planner can plan, which since [#358](https://github.com/sneakercreepers/creep/issues/358) are every calibrated class (`sqli`, `nosql_injection`, `command_injection`, `path_traversal`, `ssrf`, `template_injection`, `code_injection`, `insecure_deserialization`: 8 tasks each, 64 in all, half of them safe twins). Per-class scores are indicative only: the intervals assume independent tasks, but each class's 8 tasks come from 2 templates, so the decisions are this floor over all 64 tasks and the tier. A model is unfit when its score there is not above chance at 95% confidence (Wilson lower bound under 1/2; 40 of 64 right is the least that passes) or when it does not call at least half the safe twins safe. The scan then stops with exit `3`, sends no repository file and writes no report, and the message gives the numbers, for example `model unfit (below_chance): 32 of 64 tasks in the planned classes right (95% lower bound 0.381, ...); 32 of 32 safe twins not called safe`. The verdict is cached with the calibration, so the next scan refuses again without calibrating. `--allow-unfit-model` (a flag only, on `scan` and `resume`; no config file can set it, and `creep mcp` refuses it) scans anyway: the calibration line says `UNFIT`, and every finding from the model is labeled `unreliable_model` in the text summary, `creep why`, Markdown, SARIF and JSON v1 (`"unreliable_model": true`); findings from gitleaks and osv-scanner are not. The run is marked as well, so a run with no findings never reads clean: an `UNRELIABLE MODEL` line in the text summary and Markdown, `run.unreliable_model` in JSON v1, and a SARIF run property and error notification. Such a run writes no baseline (`--allow-unfit-model` with `--baseline-write` exits `2`) and no `--stability` record. The label never changes a status or the gate. The tier rule reads the same planned classes only ([ADR 0036](docs/adr/0036-model-fitness-floor.md)).

## Output and exit codes

`creep scan` writes `.creep/report.json` ([schema v1](docs/schemas/report-v1.json)), `.creep/report.sarif` and `.creep/report.md`, per `report.formats`. Reports from earlier runs are removed before each run. Each class is `covered`, `partial` or `not_evaluated`, with the reason. Every report also lists the classes no scan looks for (see Limits); since #365 that is the JSON `coverage.not_looked_for`, and code eval and deserialization sinks are reported as `code_injection` and `insecure_deserialization`, no longer as `command_injection`. Schema v1 changes additively only; since #26 a not-evaluated file may also have the reason `unchanged` (left out of an incremental scan).

| Code | Meaning |
|---|---|
| `0` | Nothing blocking |
| `1` | Gate exceeded: the gate of the scan's mode, `gates.pr` (default `probable:critical`), or for a nightly scan `gates.nightly` (default `verified:high`, read as `probable:high` when the nightly scan could not verify) and `gates.pr` |
| `2` | Usage, configuration or consent error |
| `3` | Model, tool canary, calibration or sandbox error, including a model calibration finds unfit (without `--allow-unfit-model`) |
| `4` | Incomplete run: report written, not everything evaluated ([ADR 0007](docs/adr/0007-exit-code-incomplete.md), [ADR 0009](docs/adr/0009-scan-and-why-contract.md)) |

An incomplete run never exits `0`, even when the gate also trips.

**Baseline.** To gate only on new findings, take a baseline from a complete scan, commit it, and pass it to every scan ([ADR 0022](docs/adr/0022-baseline-and-accepted-risks.md)):

```sh
creep scan --baseline creep-baseline.json --baseline-write   # once, from a complete run
creep accept sink-3 --expires 90d --reason "admin-only tool, fix in #12"
creep scan --baseline creep-baseline.json
```

A finding is matched by its fingerprint (class, path and redacted sink line), so lines moving do not make it new; editing the sink line does, and so does a class change: since #365 an `eval` or deserialization sink is `code_injection` or `insecure_deserialization`, so a baseline entry or accepted risk recorded for it as `command_injection` no longer matches and the finding shows up once as new; take the baseline again or accept it under its new class ([ADR 0034](docs/adr/0034-classes-not-looked-for.md)). Every entry expires (baseline entries after 90 days, accepted risks when you say, at most 365 days), and an expired entry stops suppressing. A suppressed finding is still listed, with its expiry and reason, in the text summary, Markdown, SARIF (`suppressions`) and JSON (`suppression`); only the gate skips it. A not-evaluated finding is never suppressed, and an incomplete run still exits `4`. A malformed baseline, a link in its place or an expiry over a year away exits `2`. In a pull request, read the baseline from the base commit, so the pull request cannot suppress its own finding: `git show "$BASE_SHA:creep-baseline.json" > "$RUNNER_TEMP/baseline.json"` and `creep scan --baseline "$RUNNER_TEMP/baseline.json"`.

## CI: pull request and nightly scans

The scan's mode picks the gate that judges it ([ADR 0021](docs/adr/0021-gate-per-mode.md)):

| Mode | Gate (default) | Sandbox | Chosen by |
|---|---|---|---|
| `pr` | `gates.pr` (`probable:critical`) | never: no build and no PoC, even with `sandbox.enabled`, so it never waits for verified findings | the default |
| `nightly` | `gates.nightly` (`verified:high`) and `gates.pr` | builds the app and runs PoCs when `sandbox.enabled` | `--mode nightly`, or a GitHub Actions `schedule` event |

The mode is never a config key, so the scanned repository cannot pick it; `--mode` always wins. A nightly scan also reads `gates.pr`, so it never passes what a pr scan fails. Each mode reads its keys with the same rules: the policy's `limits.gates.pr` and `limits.gates.nightly` floor both in every mode, and the project file may only make either stricter. A nightly scan that could not verify (`sandbox.enabled` false, verification unavailable for any reason, or a PoC candidate that got no run) reads `gates.nightly` at probable, `verified:high` as `probable:high`, so a finding nothing verified fails the run instead of passing it. Each scan prints its gate on stderr, for example `gate: nightly mode (GitHub Actions schedule event): gates.nightly "verified:high" (default) read as "probable:high": verification unavailable (no_runtime)`, and `creep config explain` ends with the `mode` and `gate` rows. A finding no PoC template can verify (`ssrf`, `command_injection`, `code_injection`, `insecure_deserialization`, `nosql_injection`, scanner findings) is read at probable in every nightly run, since nothing could verify it; accept one with a baseline entry ([ADR 0022](docs/adr/0022-baseline-and-accepted-risks.md)). A PoC that ran and never verified leaves its finding `probable`: `gates.pr` still fails a critical one, but a 0/5 probable high finding passes both default gates; set `gates.nightly: probable:high` in the user file or policy to fail on those too.

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
      # doctor probes the model, so it runs in the one step that has the key.
      - name: Doctor, sandbox images and nightly scan
        env:
          CREEP_POLICY: ${{ runner.temp }}/creep/policy.yaml
          CREEP_API_KEY: ${{ secrets.CREEP_API_KEY }}
        run: |
          creep doctor
          docker pull "<each image doctor lists as missing, by digest>"
          creep scan --mode nightly
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
| **v0.3** ✅ | Read-only MCP mode `creep mcp` (#32, [ADR 0027](docs/adr/0027-mcp-server.md)), recipes: format, `creep recipe` and pinned installs with `creep.lock` (#33, #34, [ADR 0025](docs/adr/0025-recipes.md), [ADR 0028](docs/adr/0028-recipe-install-and-lock.md)), public `creep bench` with safe twins and an honesty metric (#35, [ADR 0030](docs/adr/0030-creep-bench.md); published numbers synthesized at v0.3, live since #356), nightly bench CI with a release gate (regression check active once a baseline is committed) and docs-only CI fast path (#36), registry mirror for the app build (#277, [ADR 0029](docs/adr/0029-build-mirror.md)), wiki guides Writing recipes, Using creep from an agent (MCP) and Sharing model results (#38); release pentest and architecture review fixed (#330); released as [`v0.3.0`](https://github.com/sneakercreepers/creep/releases/tag/v0.3.0) (2026-11-24) |
| **v0.4** ✅ | `creep init` project template (#334, [ADR 0031](docs/adr/0031-creep-init.md)), `creep resume` continuation (#335, [ADR 0032](docs/adr/0032-resume.md)), codex checked with a ChatGPT login and `gemini` verified with an AI Studio key and `verified_env` (#333, #338); release pentest and architecture review fixed (#342); released as [`v0.4.0`](https://github.com/sneakercreepers/creep/releases/tag/v0.4.0) (2026-11-24) |
| **v0.5** ✅ | Homebrew tap and Scoop bucket published by the release workflow (#344, #346, [ADR 0033](docs/adr/0033-package-managers.md)), `go install` first in Install (#345); release pentest and architecture review fixed (#349); released as [`v0.5.0`](https://github.com/sneakercreepers/creep/releases/tag/v0.5.0) (2026-11-25) and [`v0.5.1`](https://github.com/sneakercreepers/creep/releases/tag/v0.5.1) (2026-11-26, first tap and bucket publish fixed, #352) |

Full list: the [v0.5 milestone](https://github.com/sneakercreepers/creep/milestone/7), the [wiki roadmap](https://github.com/sneakercreepers/creep/wiki#roadmap) and the [Roadmap project](https://github.com/orgs/sneakercreepers/projects/1).

## Scope and responsible use

`creep` only analyses local source code. There is no `--url` option, and there will never be evasion, persistence, lateral movement or mass scanning. If you find a vulnerability in someone else's project, follow their disclosure policy.

## Contributing

Contributions are welcome, especially **false positive** and **false negative** reports, which become test cases. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). AI-assisted contributions are fine: see [AGENTS.md](AGENTS.md). Commits on `main` must be signed (SSH or GPG) and carry `Signed-off-by` (`git commit -s`; [ADR 0026](docs/adr/0026-signed-commits.md)). To add or fix a preset, use the *Model preset* issue form ([CONTRIBUTING.md](CONTRIBUTING.md#model-presets)).

## Security

Do not open public issues for vulnerabilities in `creep`. See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
