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
