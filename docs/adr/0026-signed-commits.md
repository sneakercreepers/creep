# ADR 0026: Signed commits required on main

- **Status:** Accepted (maintainer, 2026-11-22)
- **Date:** 2026-11-22
- **Deciders:** @Ludocius
- **Changes:** the `main` ruleset (`.github/rulesets/main.json`) gains the `required_signatures` rule; AGENTS.md Conventions, CONTRIBUTING.md and GOVERNANCE.md say signing is required, not recommended
- **Fitness function:** the row "Repository settings match their files (#50)" of [architecture.md §9](../architecture.md#9-fitness-functions)

## Context

The `main` ruleset required signed commits until PR #48 removed the rule: nobody had commit signing set up, and the rule blocked every PR. #49 tracks putting it back. The maintainer now signs with an SSH key registered on GitHub as a signing key, and the agents commit through the same git configuration. A signature ties each commit on a PR to a key GitHub knows, so a commit pushed with a stolen token but without the key is shown as unverified and refused.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Keep signing recommended | No setup for contributors | An unsigned commit can reach `main`; the PR template already asks for signed commits, so policy and settings disagree |
| B. `required_signatures` on the `main` ruleset | Enforced by GitHub on every PR commit and on the squash merge, which GitHub signs itself; one rule in the file `make rulesets` applies and the drift check compares | Contributors must set up SSH or GPG signing before their first PR |

## Decision

B: the `main` ruleset requires signed commits. The rule is enforced by GitHub, not by a check we maintain, and the squash merge that lands on `main` is signed by GitHub.

## Consequences

- Contributors configure `gpg.format ssh`, `user.signingkey` and `commit.gpgsign true` and add the key on GitHub as a **Signing key** (CONTRIBUTING.md). A PR with an unsigned commit cannot merge until it is re-signed.
- The maintainer applies the rule with `make rulesets`; until then `make repo-settings-check` reports the missing rule as drift. The #49 acceptance checks (a signed PR shows `mergeStateStatus: CLEAN`, an unsigned commit is rejected) run after that.
- Tag signing is not part of this decision: release integrity rests on the cosign keyless signature and provenance (SECURITY.md).
