# ADR 0018: The docs-only shortcut excludes governance, security and ADR files

- **Status:** Accepted (maintainer, 2026-11-20)
- **Date:** 2026-11-20
- **Deciders:** @Ludocius
- **Amends:** [ADR 0002](0002-agent-loop-scope.md) (scope of the documentation-only shortcut only)

## Context

AGENTS.md lets a documentation-only change (only `*.md` or `docs/`) run only the auditor, and it excludes code, workflows, settings, the Makefile and the policy files (AGENTS.md, CLAUDE.md, CONTRIBUTING.md, the PR template). The PR #54 audit (#57) found that the shortcut still covered GOVERNANCE.md, which holds the review rules, SECURITY.md, the security policy, and `docs/adr/`, the folder through which the loop itself is changed. A PR that changed one of these ran without the tester, so the auditor was the only reviewer of the rules that govern review. The PR #282 tester also found that `docs/adr/dependencies.txt`, the dependency allowlist that `make budget` reads (invariant 6), counted as documentation.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Keep the shortcut as it is | Cheapest | The rules that govern review are reviewed by the auditor alone |
| B. Exclude GOVERNANCE.md, SECURITY.md, everything under `docs/adr/`, and `docs/adr/dependencies.txt` as a setting | These changes get the tester too; the list stays short | Every ADR, even a typo fix, runs the full loop |
| C. Drop the shortcut | Simplest rule | Wastes tokens on README and design-note edits |

## Decision

Option B. GOVERNANCE.md, SECURITY.md and everything under `docs/adr/` (including `docs/adr/dependencies.txt`, a setting `make budget` reads) are outside the documentation-only shortcut. A PR that changes any of them runs the full loop.

What decided it: these files carry governance, security policy and architecture decisions, so they get the tester as well as the auditor.

## Consequences

- AGENTS.md and CONTRIBUTING.md name the new exclusions. `internal/tools/prcheck`, which the required `docs-only` CI job runs, fails a PR that ticks the Documentation-only box and changes any of these paths, and `TestDocsOnlyMatchesAgents` keeps the code and AGENTS.md identical.
- ADR changes cost a tester run. Typo fixes in ADRs are rare, so the cost is small.
- The rest of the loop is unchanged: its roles, order, context rules and blocking rules stay as they are (ADR 0002, 0004, 0005, 0006).

## Amendments

- **An ADR for every policy change (#56, 2026-11-21).** "Changing or removing this loop needs an ADR" is now enforced, not only written. `internal/tools/prcheck`, run by the required `docs-only` job, fails every pull request that changes the policy guard or a policy file and adds or modifies no decision record (`docs/adr/NNNN-*.md`, not the template, still a regular file after the change, so a deletion does not count). Policy here is CLAUDE.md, CONTRIBUTING.md, the PR template, a nested AGENTS.md, `internal/tools/budget/policy*.go`, `internal/tools/prcheck` and the loop ADRs 0002, 0004, 0005, 0006 and 0018; the root AGENTS.md counts unless only its `## Current state` section differs from the base, so the update after each merge needs none, while the loop, invariants and conventions do. The check is static (event payload, git and the checkout, no network). Its limits: any added or modified ADR satisfies it, including an unrelated, whitespace-only or renamed one, since it cannot tell whether the ADR records the change; it runs the pull request's own `prcheck` and workflow, so a PR that edits them can switch it off, an edit that shows in the diff; Current state is free text; and pinned phrases (`make budget`, #101: whole sentences, whole template checkbox lines, HTML comments and link-reference definitions, list items and multi-line labels included, treated as hidden) cannot catch a later sentence that contradicts them, nor text kept only in an HTML attribute, a link title or image alt text. Maintainer review of the policy files stays the control. Requiring code-owner review waits for a second maintainer (GOVERNANCE.md). This strengthens the loop; its roles, order and blocking rules are unchanged.
- **Docs-only pull requests skip the heavy CI jobs (maintainer request, 2026-11-23; Accepted by that request).** The maintainer asked that documentation changes stop running the whole CI ("cuando sean docs, evita que corra todo el CI"). `paths-ignore` would leave the required checks of `.github/rulesets/main.json` pending, so CI and CodeQL call a reusable `changes` workflow (`.github/workflows/changes.yml`) that runs `prcheck -ci-scope` on the pull request's changed files and sets `docs_only`. The classification is this ADR's docs-only rule (`docsOnlyReason`, one source of truth) narrowed further: only files at the root or under `docs/`, so no `*.md` inside a package (test data, embedded text) counts, and never a doc that a check reads (`README.md`, `docs/architecture.md`, `docs/map.md`, `docs/bench/`, `docs/schemas/`, `docs/examples/`; `checkedDocs` in `internal/tools/prcheck/ciscope.go`). It is built from the base commit, so a pull request cannot change the rule that skips its own tests. On `docs_only == 'true'` the jobs `lint`, `vuln`, `workflows`, `budget`, `protections`, `action` and `analyze (go)` are skipped at job level, which GitHub reports as success for a required check, and the `test` matrix runs but skips its steps, because a skipped matrix job reports no check under its expanded name. `secrets`, `dependency-review` and `docs-only` always run. A push to `main`, the CodeQL schedule, any other event and a failed or empty classification run everything (the conditions are `!cancelled() && docs_only != 'true'`). `TestDocsOnlySkipWiring` pins the wiring. This changes which CI jobs run, not the agent loop: the docs-only box still only selects the auditor, and its required check is unchanged. Limits: a new test that reads a doc must add the path to `checkedDocs`; until then a docs-only PR that breaks it merges green and the push to `main` fails, which names it.
