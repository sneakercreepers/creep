# ADR 0031: `creep init` writes a versioned project file template

- **Status:** Accepted (maintainer, 2026-11-24)
- **Date:** 2026-11-24
- **Deciders:** @Ludocius
- **Fitness function:** the row "`creep init` never writes outside the working directory or loosens a value" of [architecture.md §9](../architecture.md#9-fitness-functions)
- **Changes:** one command, `creep init`, built after being a fail-closed stub since #1 (no new flag: it takes no argument, refuses a `--format` other than text with exit 2, and ignores the other global flags); one new public data contract, the project file template (`internal/config/project_template.yaml`, embedded, header `# creep.yaml template v1`), exported as `config.ProjectTemplate`. No new dependency, package, config key, network path or exit code.
- **Threat model:** [threat-model.md](../threat-model.md) R26

## Context

#334: `creep init` was listed as "create a creep.yaml for this project" but failed closed (exit 2, `not implemented yet`), so a new user wrote the project file by hand from the README. The project file is the untrusted layer: it comes from the repository being scanned, may only tighten what the operator set (gates only stricter, limits only lower) and cannot set where code goes, which model reads it, the sandbox, the scanners or the report outputs (#61, #62, #245, #253). `init` also runs in that repository, so whatever already sits at `./creep.yaml` (a file, a link to a path outside, a junction, a FIFO) is the repository's choice.

## Options

1. **Render the effective values.** Load every layer and write the current values. The file would then copy the operator's user file and policy into the repository, where it is committed and shared, and a later change to the user file would be silently overridden (or refused, for a raised limit) by a stale copy.
2. **Write only the keys a user is likely to change, set to their defaults.** Shorter, but a set value takes the source `project` in `config explain` and pins today's default against a later stricter built-in one.
3. **Write every project-settable key, commented out at its built-in default, with a one-line why** (chosen). The file changes no effective value until a line is edited, documents what the project layer accepts, and reads no layer.

## Decision

- `creep init` writes `./creep.yaml` in the working directory (the scan root, where `scan` reads it) from the embedded template, then prints where the operator-only settings go: `~/.creep/config.yaml`, a `--config` file or the policy (`CREEP_POLICY`), with a sample `model: preset: claude-code`. It reads no config layer, calls no model and opens no network.
- The template holds the keys the project layer accepts, outside `model.*`: `gates.pr`, `gates.nightly`, `budget.max_tokens`, `budget.max_calls`, `budget.max_seconds`, `calibration.cache_days`, `log.level`. `model.timeout_seconds` and `model.max_output_bytes` are accepted by the project layer but left out, so the file has no `model:` section that invites setting a model there. Every setting line, its section included, is commented out (`# `), so the file is a comment-only YAML document that sets nothing.
- The values are the built-in defaults, not the inherited ones. A comment says each key may only be tightened, and `creep config explain` shows the inherited value.
- **Versioning.** The first line is `# creep.yaml template v1`. Changes are additive only: a key in v1 never leaves the template (`TestProjectTemplateKeys` pins the v1 keys), and a new project-settable key outside `model.*` must be added (the same test fails when one is missing). A change that removes a key or changes a value without matching the built-in default bumps the header and needs an amendment here.
- **Tests derive from the project layer.** `TestProjectTemplateKeys` fails on a key in `projectForbidden` or under `model.`; `TestProjectTemplateValuesAreDefaults` switches every setting on and loads it as the project layer, which must accept it with every value equal to `Defaults()`; `TestProjectTemplateChangesNothing` loads defaults, policy, user and flag stacks with and without the template and compares every value and source; `TestInitWritesTemplate` compares `creep config explain --format json` before and after `creep init`.
- **Writing.** The working directory is opened as an `os.Root`. Anything at `creep.yaml` (checked with `Lstat`, never followed) is refused with exit 2 and left unchanged: a regular file as "already exists", a link, junction, directory or FIFO as "a link, directory or special file". The file is then created with `O_CREATE|O_EXCL` through that root, so one raced in after the check is refused too, and a link cannot move the write outside the root. A failed write removes the file it created.

## Consequences

- A new user gets a valid project file in one command, with no effect on the scan until they edit it, and is pointed at the operator layers for the model.
- The template is a public contract: editing a comment is free, but removing a key or changing a value is a versioned change.
- `init` never refreshes an existing file; to start over the user deletes `creep.yaml` first.
- A user file or policy that lowered a limit is not reflected in the template's values; uncommenting a line set above it fails to load with the project layer's own error, which names the inherited value.
- The `stub` helper is removed: `init` was its last caller.
