# ADR 0023: The GitHub Action contract

- **Status:** Proposed
- **Date:** 2026-11-21
- **Deciders:** @Ludocius
- **Changes:** a new stable contract, the Action at the repository root (`action.yml`: inputs, outputs, exit-code mapping, the PR comment marker); a new required CI check, `action`
- **Fitness function:** the row "The Action fails closed" of [architecture.md §9](../architecture.md#9-fitness-functions)

## Context

#29 asks for one line in a workflow: a composite `action.yml` in this repository that installs a verified creep, scans, uploads SARIF and keeps one pull request comment, and that refuses to run with secrets on pull requests from forks. The Action runs on other people's runners with their model keys and tokens, and reads a repository that is untrusted (TB1), so each of its steps is a trust boundary:

- **The binary.** Releases (#19) are signed keyless: cosign signs `checksums.txt`, and `actions/attest-build-provenance` attests every archive listed in it, from the `release` environment of `.github/workflows/release.yml`. GitHub-hosted runners ship `gh`, not cosign.
- **Secrets.** `pull_request_target`, `workflow_run` and similar events run with the base repository's secrets while the checkout can hold a fork's code. A `pull_request` from a fork gets no secrets unless the repository sends them.
- **The verdict.** The scanned repository's `creep.yaml` may lower `budget.*`, `model.timeout_seconds` and `model.max_output_bytes`. That never yields exit 0, but it turns a gate failure (1) into an incomplete run (4), because 4 wins (ADR 0007; auditor note on #29). Any softer result for 4 lets a pull request pass the gate that judges it.
- **The comment.** Report text comes from the scanned repository (file names) and the model.
- **The scope.** `--changed` (#26, ADR 0009 amendment) needs the list from the event's base commit; the baseline (#27, ADR 0022) must come from the base commit, or a pull request could suppress its own finding.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Composite action, bash scripts in `action/`, `gh` for download, attestation and comment | Tools every hosted Linux and macOS runner has; no Node bundle to review or pin; each step is a short script with tests | Bash; no Windows runner yet |
| B. JavaScript action with a bundled `dist/` | Native GitHub API client | A large generated bundle in the repository, npm dependencies (invariant 6), a second toolchain |
| C. Docker action | One environment | Linux only, pulls an image on each run, the image is a second artifact to sign |
| D. Go helper run with `go run` from the Action | Same language as creep | Needs Go of the go.mod version on the runner; a toolchain download is a network fetch outside the verified release |

| Verification option | Pros | Cons |
|---|---|---|
| a. `gh attestation verify` of the archive against the release workflow at the tag, plus its SHA-256 against `checksums.txt` | `gh` is on every hosted runner; the attestation is a Sigstore signature over the archive's digest, bound to the repository, the workflow, the tag and a GitHub-hosted runner | `checksums.txt` itself is not signature-checked (the attestation already covers the archive) |
| b. cosign `verify-blob` of `checksums.txt`, then the checksum | The README's first command | cosign is not on runners; installing it is one more download to trust |

## Decision

Option A with verification a. The one reason: it verifies with what the runner already has and keeps every step a small script whose refusals are tested.

**Inputs.** `version` (a release tag `vX.Y.Z`, prereleases included; default: the tag the Action is used at; a SHA or branch ref needs the input), `api-key` (passed to creep as `CREEP_API_KEY` in the scan step only), `config` (`--config`), `mode` (`--mode pr|nightly`, ADR 0021), `baseline` (repository-relative path; `--baseline`, ADR 0022), `incremental` (default `true`: on a pull request, `--changed` with `git diff --name-only -z "$BASE_SHA...HEAD"`), `working-directory`, `upload-sarif` (default `true`), `comment` (default `true`), `github-token` (default the workflow token), `creep-path` (self-test only, below). There is no moving `v0` tag: `v*` tags start the release workflow and releases are immutable, so a workflow pins the Action by release tag or by commit SHA with `version`.

**Outputs.** `exit-code`, and the paths `sarif`, `report` (JSON v1) and `markdown` when creep wrote them.

**Verification.** For the runner's OS (Linux or macOS) and architecture (X64 or ARM64), `install.sh` downloads `creep_<version>_<os>_<arch>.tar.gz` and `checksums.txt` with `gh release download`, requires exactly one 64-hex line naming the archive and a matching SHA-256, then runs `gh attestation verify --repo sneakercreepers/creep --signer-workflow sneakercreepers/creep/.github/workflows/release.yml --source-ref refs/tags/<version> --deny-self-hosted-runners`, and only then extracts `creep`. Any failure stops the Action before a binary runs. The tag is checked against `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$` before use.

**Fork and event policy.** `preflight.sh` runs first. Only `pull_request`, `push`, `schedule`, `workflow_dispatch` and `merge_group` run; every other event fails with a message, because those can run a fork's code with this repository's secrets. A `pull_request` whose head repository is not the base repository (or is gone) fails when any model key is present (`api-key`, `CREEP_API_KEY`, `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`), and otherwise runs without the comment (its token is read-only). The Action never checks code out; the workflow's own `actions/checkout` decides what is scanned, with `persist-credentials: false`.

**Script injection.** Every input, event field and step output reaches the scripts only through `env`; each `run` in `action.yml` is exactly `bash "$GITHUB_ACTION_PATH/action/<script>.sh"`. Inputs become flags in their `--flag=value` form after validation (enum for `mode`, `true|false` for `incremental`, a plain relative path for `baseline`, a hex SHA for the base commit). zizmor and actionlint in CI check `action.yml`.

**Verdict.** The scan step records the exit code and always succeeds, so SARIF upload and the comment run on a failed gate too; the last step fails the job on every code but 0. Exit 4 fails exactly like 1. Reports are published only after exit 0, 1 or 4, from a `.creep` that is a directory and files that are regular files (a planted report next to an exit 2 or 3 is never uploaded; threat model §6 residual), and a report the Action needs and creep did not write stops it (`report.formats` can no longer come from the project file, #253).

**Annotations.** The Action writes no annotations of its own. Code scanning annotates a pull request with the alerts its SARIF adds on changed lines, so only new findings show; with `incremental`, unchanged files are not evaluated; baseline-suppressed findings carry SARIF `suppressions` (ADR 0022), which code scanning does not show as open alerts. SARIF URIs are relative to the scan root (`SRCROOT`), so `working-directory` stays the repository root when uploading.

**Fixes.** creep outputs no fixes today, so the comment has no `suggestion` blocks. They are deferred to the v3 fix stage; the Action will add them only from a fix creep emits, never from model text the Action builds itself.

**The comment.** One comment per pull request, found by the hidden marker `<!-- creep-action:pr-comment -->` at the start of a comment by `github-actions[bot]`, updated in place (the first match) or created. The body is the marker, a verdict line from a fixed table by exit code, and `.creep/report.md` byte for byte: creep's Markdown writer puts every repository and model string in a code span with controls and format runes escaped (`internal/report` `codeSpan`), so no mention, link, HTML or table break survives. A report over 60,000 bytes is cut at a line boundary (no code span spans lines) with a note. The pull request number, repository and comment ID are checked to plain patterns before any API call.

**Permissions.** `contents: read` always; `security-events: write` to upload SARIF (and `actions: read` on a private repository, for `upload-sarif`); `pull-requests: write` only when commenting. Nothing else: a workflow in another repository reads the attestation of creep's public release without any permission; only this repository's own self-test job grants `attestations: read`, since there the token's permissions cover the release repository.

**Self-test.** CI job `action` runs `uses: ./` on three sample repositories (`internal/cli/testdata/action/app.py`): vulnerable must end failure with exit 1, clean success with 0, and one whose `creep.yaml` sets `budget.max_calls: 1` failure with 4. No release holds the code under review, and a production binary needs a model (`--replay` serves only recordings signed by the runner's own state key), so `creep-path` points at the `internal/cli` test binary, which with `CREEP_ACTION_STANDIN=<verdict>` runs the real CLI with the protection tests' fake model and fixed calibration and no network. `creep-path` skips download and verification with a warning; it is the workflow author's input, never the scanned repository's. The same job runs `install.sh` on the published `v0.1.0`, so the verification path is proven on a real release. The samples are not `testdata/apps`, which no workflow or action may name (`internal/tools/testapps` `TestNothingExecutesApps`).

## Consequences

- `action.yml` and `action/*.sh` are a contract: renaming an input or output, or changing the exit-code mapping, needs an amendment here; adding an input is additive.
- `--mode` and `--baseline` need creep v0.2 (ADR 0021, ADR 0022); with an older `version`, setting `mode` or `baseline` makes creep exit 2, which fails the job.
- Windows runners are refused until a release check for the `.zip` archives is added.
- `internal/tools/actionscripts` tests every script's refusals under bash with fake `gh` and `creep`; they skip on Windows and run in the Linux CI test job.
- No dependency is added.
