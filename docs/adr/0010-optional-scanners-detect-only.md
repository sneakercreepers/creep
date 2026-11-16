# ADR 0010: Optional scanners are detected, not run, and listed in the report

- **Status:** Accepted (maintainer approval on PR #218, 2026-11-16)
- **Date:** 2026-11-16
- **Deciders:** @Ludocius
- **Changes:** the JSON report schema v1 (adds `coverage.scanners`), the Markdown and SARIF reports, the `creep scan` text summary

## Context

#10 makes gitleaks, osv-scanner and semgrep optional: used when installed and enabled (`scanners.enabled`), otherwise the report says what they would have covered. Its acceptance criteria are that a missing tool never fails a scan and that the coverage section lists each missing tool with the classes it would cover.

Running them is a different matter:

- No shipped package may import `os/exec` (`internal/tools/budget/imports.go`, `execAllowed`): running a program is a way around invariant 1 and invariant 5.
- semgrep with registry rules and osv-scanner without a local database call the network, which invariant 5 forbids outside configured model endpoints.
- Their output holds repository text and, for gitleaks, the secrets themselves, so parsing it into the report needs its own redaction and escaping rules.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Run the tools now (offline flags, timeouts, SARIF parsing) | Real extra coverage | Opens `os/exec` in the product; network-free modes differ per tool and version; secrets in gitleaks output; far beyond the acceptance criteria |
| B. Detect only, list every scanner and its classes as not evaluated | Meets the acceptance criteria; no program runs on the host; the product keeps no `os/exec` | Installing a tool adds no coverage yet |
| C. Say nothing about scanners | No change | The report hides classes nobody evaluated |

## Decision

Option B. What decided it: the acceptance criteria need only honest reporting, and B keeps creep from running any program on the host.

- `static.DetectScanners` looks each enabled scanner up by its exact name on `PATH`, the way the OS would (empty entries mean the current directory; Windows searches the current directory first and uses `PATHEXT`; elsewhere a file needs an execute bit). It never executes anything and does not import `os/exec`. The first match decides: a match in a relative `PATH` entry, in the repository or the current directory, or a link that resolves into the repository, is **refused** rather than skipped for a later one, since that is the binary a shell would run.
- The report gains an optional `coverage.scanners` array (schema v1, amended additively as ADR 0009 allows before the first release): `{name, status, classes}`. `status` is `not_enabled`, `missing`, `refused` or `not_run` (installed but not run by this version). Names and classes are IDs; no path, version or tool output is stored, so nothing from the host or the repository reaches the report.
- Classes: gitleaks `hardcoded_secret`; osv-scanner `vulnerable_dependency`; semgrep `xss`, `insecure_deserialization`, `weak_crypto` (rule classes the reader does not evaluate). The CLI maps them by explicit switch.
- None of these statuses makes the run incomplete or changes the exit code: like `nosql_injection` and the other classes the pipeline cannot read, they are listed, not counted as gaps (ADR 0009 counts files and sinks).
- Markdown adds an "Optional scanners" section, SARIF a `note` notification per scanner (`creep/scanner/<status>`), and the text summary one `scanner` line per scanner.

## Consequences

- Running a scanner later needs its own ADR: an `execAllowed` entry for one package, fixed argument lists, no shell, a timeout and an output cap, offline modes only, and redaction and escaping of the tool's output. The refusal rules above already decide which binary may run. *Qualified by [ADR 0013](0013-scanner-runner.md): string comparison missed Windows junctions and `\\?\` paths, so a runner relies only on the final-path, file-identity rule there.*
- `creep doctor` (#6) can reuse `DetectScanners` to show the same states.
- Tests: `internal/static/scanners_test.go` (absent, present, inside the repository, first match wins, relative and empty `PATH` entries, no repository, execute bit and links on Unix) and `internal/cli/scanners_test.go` (every state through `creep scan` exits 0 with a complete run and lists the scanner and its classes).
