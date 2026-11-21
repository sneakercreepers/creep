// Command prcheck fails a pull request that claims the docs-only shortcut
// but changes more than documentation, or changes the agent-loop policy
// without an ADR.
//
// AGENTS.md lets a documentation-only change run only the auditor. The
// claim was a self-declared checkbox that nothing compared with the files
// the PR changes (#57). The CI docs-only job runs this command on every
// opened, edited, reopened or updated pull request: when the body ticks the
// Documentation-only box, every changed path must fit the shortcut as
// AGENTS.md defines it: only *.md files or docs/, and not code, workflows,
// settings (docs/adr/dependencies.txt, which make budget reads, included), a
// Makefile, a policy file (AGENTS.md, CLAUDE.md, CONTRIBUTING.md, the PR
// template), GOVERNANCE.md, SECURITY.md or anything under docs/adr/ (ADR
// 0018). A body that does not tick the box claims nothing and passes;
// the full loop applies to it.
//
// Every pull request that changes the policy guard or a policy file must
// also add or modify a decision record (docs/adr/NNNN-*.md, not the
// template) that is still a regular file after the change (#56, ADR 0018
// amendment). Policy here means CLAUDE.md, CONTRIBUTING.md, the PR template,
// a nested AGENTS.md, internal/tools/budget/policy*.go,
// internal/tools/prcheck and ADRs 0002 and 0018; the root AGENTS.md counts
// only when its "## Workflow (spec-driven)" section differs from the base,
// so a Current state update needs no ADR. Which ADR, and whether it records
// the change, stays with review.
//
// It reads only the event payload GitHub writes to disk, the changed-file
// list and the base AGENTS.md from git, and the checked-out tree, so it
// makes no network call. Inputs it cannot read, and an event without a pull
// request, fail the check (exit 2). The box is found in
// the raw body, comments and blockquotes included, so a parser mismatch with
// GitHub can only fail the check.
//
// It is a static backstop for honest mistakes, not proof: a PR controls the
// code its own checks run, and a PR that edits this command or its workflow
// is not documentation-only. Review stays required.
package main
