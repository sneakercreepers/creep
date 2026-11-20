// Command prcheck holds a pull request to the agent loop it declares in its body.
//
// AGENTS.md makes every model-assisted change run the loop and link its
// outputs, and lets a documentation-only change run only the auditor. Both
// were self-declared checkboxes that nothing compared with the PR (#57, #58).
// The CI pr-body job runs this command on every opened, edited, reopened or
// updated pull request:
//
//   - A ticked "AI-assisted:" loop box must link at least two comments on this
//     PR (tester verdict, auditor decision), three when the external
//     contributor box is ticked too (the security review).
//   - A ticked "Documentation-only" box must link at least one comment on this
//     PR (the auditor decision), and every changed path must fit the shortcut
//     as AGENTS.md defines it: only *.md files or docs/, and not code,
//     workflows, settings, a Makefile or a policy file (AGENTS.md, CLAUDE.md,
//     CONTRIBUTING.md, the PR template).
//
// It reads only the event payload GitHub writes to disk and the changed-file
// list from git, so it makes no network call. A link counts when it names
// this repository, this PR and a comment, review or review comment anchor; a
// placeholder, a bare URL or a link to another PR does not, nor does a link
// inside an HTML comment, closed or not. A ticked box counts wherever it is,
// even where a comment might hide it, so hiding text never switches the
// check off.
//
// It is a static backstop for honest mistakes, not proof: it cannot see that
// a linked comment exists or which head it judged, and a PR controls the code
// its own checks run. Review stays required.
package main
