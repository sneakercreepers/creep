# ADR NNNN: <short title>

- **Status:** Proposed | Accepted | Superseded by ADR-NNNN
- **Date:** YYYY-MM-DD
- **Deciders:** @handle
- **Amends:** ADR-NNNN (only when this ADR changes part of an earlier one; add a matching **Amended by:** line to that ADR's header)
- **Fitness function:** the row of [architecture.md §9](../architecture.md#9-fitness-functions) that guards this decision, or `manual: auditor`

## Context

What problem forces a decision? Constraints, evidence, numbers.

## Options

| Option | Pros | Cons |
|---|---|---|
| A | | |
| B | | |

## Decision

What we chose and the one reason that decided it.

## Consequences

What becomes easier, what becomes harder, what we must now do (tests, docs, follow-up issues).

For an ADR that adds a dependency, Consequences records the module's SPDX license (for example `MIT`); the auditor checks the license again on any `go.mod` version bump of a direct dependency.
