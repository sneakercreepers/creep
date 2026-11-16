# Contributing to creep

Thanks for helping. The most valuable contributions are often not code:

- **False negative**: a vulnerability `creep` missed. Use the *False negative* issue form with a minimal vulnerable example. It becomes a test case.
- **False positive**: a finding that is wrong. Use the *False positive* issue form.
- **Model results**: calibration or benchmark results with your model. Post them in [Discussions → Show and tell](https://github.com/sneakercreepers/creep/discussions/categories/show-and-tell).
- **Recipes and model presets**: data, not code. See the issue forms and [Model presets](#model-presets).

## Before you start

1. Look for an existing issue. If none exists, open one before writing code that is larger than a typo fix.
2. Changes that add a dependency, change a public contract (CLI flags, exit codes, JSON/SARIF output, config keys) or touch security-sensitive areas need an [ADR](docs/adr/0000-template.md) first.
3. Security-sensitive areas: `internal/gateway` (including `egress.log`), `internal/redact`, `internal/models`, `internal/reader`, `internal/static`, `internal/planner`, `internal/sandbox` (v0.2), every `prompts/` directory and `.github/workflows`. PRs touching them get the `security-sensitive` label and require the threat-model checklist in the PR template: check the change against [docs/threat-model.md](docs/threat-model.md) and update it when a trust boundary, threat or mitigation changes.
4. Read [docs/map.md](docs/map.md) (one line per package, with its layer) and [docs/architecture.md](docs/architecture.md) before exploring the tree.

## Development setup

You need Go, make and git. Nothing else: the dev tools are Go programs under `internal/tools`, run by make with `go run`.

```sh
make check                          # fmt, tidy, vet, budget, map freshness and tests (CI also runs golangci-lint, govulncheck, gitleaks)
make budget                         # dependency allowlist, import and layer rules, module/binary caps, file length, workflow pinning
make test PKG=./internal/redact     # one package
make map                            # regenerate docs/map.md after adding, removing or renaming a package or changing the first sentence of a doc.go
```

Every package needs a `doc.go` whose first sentence says why it exists: `make map` copies that sentence into the map and fails without it, and `make check` fails when the committed map is stale.

Tests never call a real model, so they need no key and no network. Reader tests replay recorded replies from `internal/reader/testdata/replay`; CLI tests use fakes and recorded runs:

```sh
go test ./...                                           # replays deterministically, no keys needed
go test ./internal/reader -run TestAppsReplay -update   # regenerate reader fixtures after changing a prompt, the schema, slicing or an app
```

`creep scan --record` records a live run under `.creep/`, and `creep scan --replay` serves it back with no network.

## Model presets

A preset is one YAML file in [`internal/presets/`](internal/presets/), embedded in the binary and selected with `model: { preset: <name> }` in the user file, `--config` or the policy (never the repository's `creep.yaml`). To add or fix one, open the [**Model preset** issue form](https://github.com/sneakercreepers/creep/issues/new?template=6-model_preset.yml) first, with the CLI version, the proposed file and the canary output below.

```yaml
version: 1                     # schema version
name: claude-code              # equals the file name; lowercase letters, digits, dashes
description: One line.
docs: https://...              # the CLI's flag reference
program: claude                # bare program name, found on PATH; never a path or a command line
args: [-p, --tools, "", --strict-mcp-config, --output-format, text]   # a list, never a shell string
tools_off:                     # every argument run that switches tools off; each must be in args
  - [--tools, ""]
  - [--strict-mcp-config]
no_tools: false                # true (with tools_off: []) only for a CLI that has no tools
host_reads: none               # none: nothing can read outside the empty working directory
                               # unbounded: some tool can still read HOME or the web; then also
# host_reads_detail: one line naming what can still read (printed as a warning at doctor and scan)
verified: false                # true only after the manual canary check below passed with the real CLI
```

The canary only sees writes, so `host_reads` is declared, not tested: say `unbounded` whenever a read-only tool, a shell under a read-only sandbox, web search or user MCP servers can remain.

`{model}` as a whole argument is replaced by `model.name`. Unknown or duplicate keys fail `TestEmbeddedPresets`, which `make check` and CI run. The CLI must read the prompt on stdin and print only the reply on stdout; comment each flag in the file and say what you could not verify.

### Manual canary check and `verified`

CI cannot run real model CLIs. A preset ships with `verified: false` until someone runs this check with the real CLI (installed and logged in); until then `creep doctor` and every scan print a one-line warning that it is unverified. The automatic tool canary runs on every scan either way.

To verify a preset:

1. Run the check below and record the CLI version.
2. Open the [**Model preset** issue form](https://github.com/sneakercreepers/creep/issues/new?template=6-model_preset.yml) with the preset file, the CLI version and the full `creep doctor` output of both commands (the passing check and the tools-on control).
3. A maintainer reviews the output, then a PR sets `verified: true` in that preset (a later change to its `program` or `args` must set it back to `false` until checked again; reviewers check this).

Run it from a new empty directory, with no `creep.yaml`, and the config file outside it:

```sh
cd "$(mktemp -d)"
printf 'model:\n  preset: <name>\n' > ../preset-check.yaml           # ollama: add "  name: <model>"
creep --config ../preset-check.yaml config explain | grep model.run   # the command line from the preset
creep --config ../preset-check.yaml doctor
```

Expected: `doctor` asks for consent to the `command://<program>-<hash>` endpoint, then prints `tool canary passed (no file was created and no command ran)` and exits 0. A preset is rejected if `doctor` prints `has tools enabled` (exit 3), or if the canary cannot run (exit 3: fix the flags, the login or the timeout). Then check the opposite, to prove the canary reaches the CLI: run the same command line with its tools on, without the preset, and confirm `doctor` fails with exit 3 and names the flag:

```sh
printf 'model:\n  contract: command\n' > ../tools-on.yaml
creep --config ../tools-on.yaml --model-run 'claude -p --dangerously-skip-permissions --output-format text' doctor
# gemini: 'gemini --approval-mode yolo'   codex: 'codex exec --sandbox workspace-write --skip-git-repo-check -'
```

Delete the temporary directory and the two config files afterwards.

| Preset | `verified` | Help wanted |
|---|---|---|
| `claude-code` | `true` | |
| `gemini` | `false` | run the check with Gemini CLI |
| `codex` | `false` | run the check with Codex CLI |
| `ollama` | `false` | run the check with Ollama and a local model |

## Pull requests

- One logical change per PR. Small PRs get reviewed faster.
- Branch from `main`. PRs are squash-merged; `main` has linear history.
- Title in [Conventional Commits](https://www.conventionalcommits.org/) format: `feat(redact): detect JWTs`.
- **Signed commits** (SSH or GPG) are recommended and will become required on `main` once the maintainer has signing set up ([#49](https://github.com/sneakercreepers/creep/issues/49)). See [GitHub docs](https://docs.github.com/authentication/managing-commit-signature-verification).
- **DCO**: every commit needs `Signed-off-by` (`git commit -s`). By signing off you certify the [Developer Certificate of Origin](https://developercertificate.org/). We do not use a CLA.
- Add a release-note label (see below).

### Release-note labels

| Label | Section in release notes |
|---|---|
| `breaking` | ⚠️ Breaking changes |
| `security` | 🔒 Security |
| `affects-results` | 🎯 Changes that affect results (prompts, rules, calibration) |
| `type/feature` | ✨ New |
| `type/bug`, `type/false-positive`, `type/false-negative` | 🐛 Fixes |
| `type/docs` | 📚 Documentation |
| `type/chore` | 🧰 Maintenance |
| `skip-changelog` | hidden |

`affects-results` matters: when prompts, rules or calibration change, users' results and CI baselines can shift.

## Repository rules

Rulesets live in [`.github/rulesets/`](.github/rulesets/) and are applied with `make rulesets` (creates or updates by name), which also applies [`.github/settings/`](.github/settings/): Actions permissions (full-SHA pinning required) and the `release` environment. Change them by PR, never only in the UI.

- `main`: PR required, squash only, linear history, no force push or deletion, and all CI jobs green. No bypass actors, not even admins.
- `release-tags`: `v*` tags can never be moved or deleted. `release-tag-creation`: only repository admins can create `v*` tags.
- Single-maintainer phase: PRs need 0 approvals and code-owner review is off. With two or more maintainers, raise approvals and turn on `require_code_owner_review` (see [GOVERNANCE.md](GOVERNANCE.md)).

## Releasing

Maintainers only. Versions follow [SemVer](https://semver.org/); pre-releases are `vX.Y.Z-rc.N`. Before 1.0 a minor release may break things and says so under ⚠️ Breaking changes.

1. Close the milestone: every issue done or moved. Run the release pentest ([ADR 0004](docs/adr/0004-pentester-per-release.md)) and the architecture review with its wiki diagram update ([ADR 0005](docs/adr/0005-auditor-architecture-review.md)); a confirmed Critical or High blocks the release.
2. Tag a release candidate on `main` and push it: `git tag -a v0.1.0-rc.1 -m v0.1.0-rc.1 && git push origin v0.1.0-rc.1`.
3. Approve the `release` environment deployment. The environment only accepts `v*` tags, needs the maintainer's approval (admins cannot bypass it) and is the only place release credentials (OIDC) are available.
4. The [release workflow](.github/workflows/release.yml) checks the tag's ancestry, builds with goreleaser ([`.goreleaser.yaml`](.goreleaser.yaml)), signs `checksums.txt` with cosign keyless, adds an SBOM per archive and a build provenance attestation, uploads a draft, runs the [verification commands](SECURITY.md#verifying-a-release) against it and only then publishes it. Notes are generated by category from [`.github/release.yml`](.github/release.yml); anything labelled `affects-results` must be called out, because users' results and baselines will shift.
5. Check the published release candidate with the README verification commands, then tag the final version on the same commit (`v0.1.0`) and repeat steps 3 and 4.

To try the release build without releasing, run the workflow by hand (Actions → Release → Run workflow) or open a PR touching the release files: it builds a snapshot twice, checks the binaries are reproducible and tests the ancestry guard, with no secrets, no signature and nothing published.

Tags are immutable (ruleset) and so are published releases (immutable releases are enabled). A mistake means a new version, never a moved tag.

Rulesets cannot enforce "a `v*` tag points to a commit on `main`". The release workflow ([#19](https://github.com/sneakercreepers/creep/issues/19)) checks ancestry before building and refuses a tag whose commit is not on `main`, the only branch a ruleset protects. A `release/*` branch would need its own ruleset first.

**Hotfix** (patch without shipping unreleased work from `main`). Not available yet: the ancestry guard accepts only `main` until a ruleset in `.github/rulesets/` protects `release/*` like `main` (PR-only, required checks, no force push or deletion), the maintainer applies it with `make rulesets`, and the guard is extended to it. Until then a patch is tagged on `main`. Once it is enabled:

1. Fix on `main` first, through a normal PR.
2. Branch from the release tag: `git switch -c release/v0.1 v0.1.0` (reuse the branch if it exists) and push it.
3. Cherry-pick the squash commit: `git cherry-pick -x -s <sha>`, then push.
4. Tag the patch from that branch: `git tag -a v0.1.1 -m v0.1.1 && git push origin v0.1.1`, then follow Releasing steps 3 to 5.

## AI-assisted contributions

Welcome. Declare it in the PR template. You are responsible for every line you sign off. Agents should read [AGENTS.md](AGENTS.md).

Model-assisted changes go through the agent loop **developer → tester → pentester → auditor** (details in [AGENTS.md](AGENTS.md#workflow-spec-driven), rationale in [ADR 0002](docs/adr/0002-agent-loop-scope.md)). Developer, tester and auditor share context. The pentester gets no shared context. The pentester runs once per version, over the whole version diff before the release is tagged, and on every pull request from an external contributor ([ADR 0004](docs/adr/0004-pentester-per-release.md)). A confirmed Critical or High from the release pentest blocks the release. The `security-sensitive` label, which only maintainers apply, marks what the release pentest must cover first. If the auditor sees security impact in an unlabeled change, it asks a maintainer to add the label so the release pentest covers it. Link the tester verdict, the security review (when the pentester ran) and the auditor decision in the PR. A confirmed Critical or High finding blocks the merge. Documentation-only changes run only the auditor (only `*.md` or `docs/`; not code, workflows, settings or the policy files). The auditor triages every open finding and adds the follow-up issues to the project board. Changing or removing this loop needs an ADR and maintainer approval.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
