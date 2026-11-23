# ADR 0028: Installing recipes pinned by commit, with `creep.lock`

- **Status:** Accepted (maintainer, 2026-11-23)
- **Date:** 2026-11-23
- **Deciders:** @Ludocius
- **Amends:** [ADR 0025](0025-recipes.md) (decision 6: `creep scan` now loads installed recipes, only after lock verification and `Checker.Load`)
- **Changes:** a new command, `creep recipe add github.com/<owner>/<repo>@<commit> <clone>`; a new stable file format, `creep.lock` (`recipe.Lock`, version 1) in `~/.creep/recipes/`; a new policy-only field, `recipe_sources` (`config.Resolved.PolicyRecipeSources`), which is not a config key; `scan` gives the reader a recipe hint (`reader.Target.Hint`) and plans hinted steps with `reader.HintNoteTokens`
- **Fitness function:** the row "An installed recipe is used only as pinned, checked and allowed" of [architecture.md §9](../architecture.md#9-fitness-functions)

## Context

#34 asks for community recipes that are reproducible and tamper-evident: `creep recipe add github.com/<owner>/<repo>@<sha>`, branch names and tags refused, checksums in `creep.lock`, a mismatch failing the scan, and an org policy that may allowlist sources. ADR 0025 left three promises for it: recipes come from the operator's side only, pinned by commit; an org policy may allowlist sources; and the project file may at most drop a recipe, never add one.

Fetching from GitHub collides with two invariants. Invariant 1: only `internal/gateway` may open a network connection. Invariant 5: no network call except to configured model endpoints. A recipe fetch is neither a model call nor to a model endpoint, so any design where creep itself downloads a repository either breaks invariant 5 or adds a second kind of egress to the gateway, with its own allowlist, consent, logging and TLS rules, for a command that runs rarely.

Recipes are untrusted third-party text (ADR 0025, TB10). The new threats are a source that moves under its name (a branch or tag repointed), an installed file changed after review (on disk, by another local program or a careless edit), and a recipe source the organization has not reviewed.

## Options

| How creep gets the recipe bytes | Pros | Cons |
|---|---|---|
| A. creep downloads a tarball or clones over HTTPS (`codeload.github.com`) through a new gateway egress kind | One command; creep can check the commit itself | Breaks invariant 5, or needs a second egress class in the gateway (allowlist, consent, egress.log, TLS and DNS pinning for a non-model host); creep would need a git object or tar reader for untrusted archives |
| B. creep runs `git clone` and `git checkout` itself | Uses git's own verification | Product `os/exec` outside gateway, scanrun and sandbox (budget rule); git does network I/O on creep's behalf, which invariant 5 forbids; git config, hooks and credential helpers of the host run inside a creep command |
| C. The operator clones the source and checks out the commit with git; `creep recipe add <source>@<commit> <clone>` checks the clone and copies its recipe files | creep makes no network call and starts no program, so invariants 1 and 5 are untouched; the operator sees and controls the fetch; no new dependency | Two steps for the operator; creep trusts the clone's working tree, which it does not re-hash against the commit (see Consequences) |

| Where the lock and installed files live | Pros | Cons |
|---|---|---|
| a. `creep.lock` and `recipes/` in the scanned repository | Teams share pins in version control | The repository is attacker-controlled (TB1): a pull request adds a lock entry and a recipe that clears its own sink; the project file would add, not only drop (ADR 0025 option a) |
| b. `~/.creep/recipes/creep.lock` with files under `~/.creep/recipes/<owner>/<repo>/<commit>/`, the operator's home next to the user config | Operator side only; the scanned repository never supplies one | Each runner installs its own; teams share pins through the org policy and their runner setup, not the repository |

| What a pin is | Pros | Cons |
|---|---|---|
| i. Anything `git rev-parse` takes (branch, tag, short SHA) | Convenient | Names that can move or collide; not reproducible |
| ii. A full 40-hex lower-case SHA-1 commit ID only | Exactly one commit; refused before anything is read | SHA-256 repositories are not supported yet |

| Allowlist | Pros | Cons |
|---|---|---|
| α. A config key (`recipes.allow`) any layer may set | Uses the layered config | A user or `--config` layer could lift it unless locked; one more key the project file must be kept from |
| β. A policy-only field `recipe_sources`, like `consent`: not a `Config` key, so no user, project or `--config` file can express it | The org decides alone; a project file naming it fails to load (unknown key) | The operator cannot narrow it in their own config (they can simply not install) |

## Decision

**C, b, ii and β.** creep never fetches a recipe; the operator does, with git, and creep verifies what it copies. The deciding reason: the invariants stay intact with no new egress or process, and every control (pin, checksum, allowlist) is enforced by creep on bytes it reads locally.

1. **`creep recipe add github.com/<owner>/<repo>@<commit> <clone>`.** The source must be `github.com/<owner>/<repo>` with GitHub's name rules (lower-cased; owner 1 to 39 of `a-z0-9-`, repository 1 to 100 of `a-z0-9._-`, never `.` or `..`) and the pin a full 40-hex lower-case commit; a branch, a tag, a short or upper-case SHA is refused before anything is read (`recipe.ParseSource`, `ErrSource`, exit 2). The org policy must allow the source (5). The clone is opened as an `os.Root`: `.git` must be a directory (a worktree's or submodule's `.git` file is refused, so creep never follows a `gitdir:` path), `.git/HEAD` must be the detached pinned commit (`recipe.DetachedHead`; a symbolic HEAD is a branch), and `[remote "origin"]` in `.git/config` must be that repository (`recipe.OriginRepository`; https, `git@` and `ssh://` GitHub forms). Recipe files are the `*.json` files directly in the clone's `recipes/` directory: 1 to 32, each named `a-z0-9-_` with `.json` (`recipe.ValidFileName`, also no Windows device name), regular, singly linked, capped at 64 KiB, and valid (`recipe.Parse`, no model call). Any fault installs nothing (exit 2). creep never runs git and makes no network call.
2. **Install.** Inside `~/.creep/recipes` (an `os.Root`; the store must be a directory, not a link): the files are written exclusively (`O_EXCL`, 0600) under `<owner>/<repo>/<commit>/`, then `creep.lock` is replaced through a temporary file and a rename, then the source's other commit directories are removed. The new lock is marshalled and parsed back before anything is written, so creep never writes a lock its own scan would refuse. Installing a source again replaces its entries; other sources are kept.
3. **`creep.lock` (version 1).** Closed JSON, decoded as strictly as a recipe (unknown, repeated and case-variant keys, trailing data refused; at most 256 KiB and 256 entries): `{"version": 1, "recipes": [{"source", "commit", "file", "checksum": "sha256:<hex>"}]}`. Each entry's source is canonical, its commit a full SHA, one commit per source, no file listed twice, and every path segment a single safe name, so a tampered lock cannot point outside the store (`recipe.ParseLock`, `ErrLock`).
4. **Scan.** Before a session, state or model is opened, `scan` reads the lock and, for every entry, checks the policy, reads the file (no link, special file or hard link, capped), compares its SHA-256 in constant time (`Pin.Verify`) and parses it. Any fault (a changed, missing or added-to-lock file, a refused lock, a source the policy no longer allows) fails the scan closed with exit 2 (ADR 0007: configuration) and no model call. After the tool canary and calibration, each recipe goes through `recipe.Checker.Load` at the calibrated tier, the only way to a usable recipe (ADR 0025); a refused recipe exits 2 and a model failure 3, before discovery. No entry is ever skipped, so a scan never runs with fewer recipes than the lock lists. A hypothesis gets, through `reader.Target.Hint` only, the hint of the first recipe in lock order whose class and `applies_to` extension cover it; nothing else of a recipe leaves `internal/recipe`, and the planner still sees none of it. When recipes are loaded, each planned step costs `reader.HintNoteTokens` more, per `--stability` sample. With no store or an empty lock, a scan is byte for byte what it was.
5. **Policy.** The org policy (`CREEP_POLICY`) may list `recipe_sources`: entries `github.com/<owner>/<repo>` or `github.com/<owner>/*`, matched case-insensitively, a pinned entry refused (the lock pins, the policy names). Absent, the operator decides alone; present, only listed sources may be installed and loaded, and an empty list allows none. A bad entry is a configuration error for every command (`recipe.CheckAllowlist`). It is not a `Config` key, so the user file, `--config` and the project file cannot express it: a `creep.yaml` that names it fails to load.
6. **The scanned repository never supplies a recipe.** A `creep.lock`, `recipes/` or `.creep/recipes/` in the repository is never read; only the operator's home store is. No config key names a recipe; the project file cannot add one. ADR 0025's "the project file may at most drop recipes" stays a possibility for a later key; this version has none.

## Consequences

- Easier: a team pins a reviewed recipe commit, every scan proves it still has exactly those bytes, and the org can bound which sources its runners load, with no network path beyond the model endpoint.
- Harder: the operator runs `git clone`, `git checkout --detach <sha>` and `creep recipe add`; every scan with recipes makes two model calls per recipe file for its fixtures (counted by the gateway's budget and `--stats`, not yet by `creep estimate`). A recipe that fails its fixtures at the scan's tier fails the scan until it is reinstalled or removed from the lock.
- Residual: creep checks the clone's HEAD and origin but does not re-hash the working tree against the commit's tree, which would need a git object and packfile reader; an operator who edits a recipe in the clone before `add` installs the edit under the commit's name. The origin check reads only the clone's `.git/config` and takes only the `https://`, `git@` and `ssh://git@` forms (a bare `github.com/<owner>/<repo>`, which git reads as a local path, is refused); a `url.<base>.insteadOf` rewrite in the operator's git config is not seen. The clone is the operator's own, and the lock makes any change after install visible. The lock and the files share the operator's home, so the account that can write both can re-pin (threat model L5, like L4 for `egress.log`). Only github.com and SHA-1 repositories are supported.
- `--config` replaces the user and project config files, not the recipe store: a CI job that wants no recipes runs on a home without `~/.creep/recipes`, or with a policy `recipe_sources: []`.
- Tests: `internal/recipe` (`source_test.go`, `lock_test.go`: pins, allowlist, clone files, hints, lock format, tampering), `internal/cli/recipeadd_test.go` (install, refusals, linked clones, usage), `internal/cli/recipescan_test.go` (scan loads only verified and passing recipes, tampering fails closed, policy enforced on add and scan, the project file and the repository cannot add sources). Docs: architecture §3, §5, §9 and the ADR index; threat model TB10, §4.4 (L5), §4.8 (RC5, RC8 to RC11) and §7.
