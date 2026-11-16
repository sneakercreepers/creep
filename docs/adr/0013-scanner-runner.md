# ADR 0013: Run gitleaks and osv-scanner offline from one package

- **Status:** Proposed (maintainer approval required before merge)
- **Date:** 2026-11-16
- **Deciders:** @Ludocius
- **Changes:** the `execAllowed` rule in `internal/tools/budget` (one new package, `internal/scanrun`); the JSON report schema v1 (`coverage.scanners[].status` gains `evaluated` and `failed`, amended additively as ADR 0009 allows before the first release); the Markdown and SARIF scanner sections and the `creep scan` text summary; the `scanners.enabled` project-file rule
- **Qualifies:** [ADR 0010](0010-optional-scanners-detect-only.md) (Consequences)

## Context

ADR 0010 made gitleaks, osv-scanner and semgrep optional and detect-only: they are looked up on `PATH` and listed as not evaluated. #221 asks to run them. That is the first product code that starts another program, so it can bypass invariant 1 (network only through the gateway) and invariant 5 (no network except model endpoints), and it can execute something the scanned repository planted (invariant 4's spirit: the host runs nothing the repository chose).

Review of PR #218 found two gaps that a runner would inherit:

- Detection compared paths as strings after `filepath.EvalSymlinks`. Since Go 1.23 that no longer follows Windows junctions (mount points), and a `\\?\` verbatim `PATH` entry does not compare as inside the repository, so both were reported `not_run` instead of `refused` (tester finding 1, Low).
- The scanned repository's `creep.yaml` could set `scanners.enabled` (finding 2, Info). Once enabling means running, that is a repository choosing which programs run on the operator's machine (#62).

What each tool needs to run without the network (from each tool's documentation):

| Tool | Offline invocation | Repository-chosen config it would read | Network if misused |
|---|---|---|---|
| gitleaks v8 | `detect --no-git --source <repo>` scans files only, no git history and no `git` binary | `<repo>/.gitleaks.toml` (replaces the rules), `<repo>/.gitleaksignore`, inline `gitleaks:allow` | none |
| osv-scanner v2 | `scan source --recursive --offline` with a local database (`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`); never `--download-offline-databases` | `osv-scanner.toml` per directory (ignores advisories) | database download, registry resolution, deps.dev |
| semgrep | `--metrics=off --config <local rules>` | `.semgrepignore`, any `--config` the repository suggests | registry rules (`--config auto`, `p/...`), metrics, version check |

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Keep detect-only (ADR 0010) | No program runs | Installed tools add no coverage |
| B. Run each tool from the package that knows it (`static`, `cli`) | No new package | `os/exec` spreads across packages that also handle repository text; the exec rule loses its single review point |
| C. One package, `internal/scanrun`, is the only product code allowed `os/exec`; fixed offline invocations; everything else stays not run | One reviewed place; fixed arguments; failures are visible | gitleaks and osv-scanner only; semgrep needs rules creep does not ship |

## Decision

Option C. What decided it: one package with fixed arguments keeps the exec path as small and reviewable as the gateway keeps the network path.

**Which binary may run.** `static.DetectScanners` keeps its first-match rule and now resolves the match to its **final path**: every symbolic link and every junction is followed component by component (`os.Lstat`, `os.Readlink`, at most 64 hops), `\\?\` and `\??\` prefixes are removed, and a volume-GUID target or any error fails closed. The final path and each directory above it are then compared with the repository and the working directory by **file identity** (`os.Stat` + `os.SameFile`), so case, 8.3 names, `subst` drives and roots reached through links all match. A match inside is `refused`. The runner executes that final path, never the name looked up again, and repeats the check right before starting it (`static.OutsideRepo`). On Windows only an `.exe` runs: `CreateProcess` would run a `.bat` or `.cmd` through `cmd.exe`. No new dependency: `GetFinalPathNameByHandle` would need `golang.org/x/sys` or `unsafe`, both barred.

**Who may enable a scanner.** Only the user file, `--config` or the org policy. The project file (the scanned repository's `creep.yaml`) may only remove scanners an earlier layer enabled; adding one is a config error (exit 2) that names the project file. `creep config explain` shows which layer set the key.

**How it runs.**

- `exec.CommandContext` with the final path and a fixed argument list per tool; the repository root is the only variable and is passed as one absolute argument. No shell.
- gitleaks: `detect --no-git --source <repo> --config <tmp>/gitleaks.toml --gitleaks-ignore-path <tmp>/ignore --report-format json --report-path <tmp>/report.json --redact --no-banner --log-level error --exit-code 0`. creep's config only extends the built-in rules (`[extend] useDefault = true`), so a repository's `.gitleaks.toml` and `.gitleaksignore` are not read. `--redact` keeps secrets out of the report. Inline `gitleaks:allow` comments still suppress single findings: a residual risk the report cannot see.
- osv-scanner: `scan source --recursive --offline --config <tmp>/osv-scanner.toml --format json --output <tmp>/report.json <repo>`, with `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` taken from the operator's environment. Without it, or with a relative path, osv-scanner is `not_run`: it would need the network. A database inside the repository or the working directory is `refused`. The empty `--config` replaces any `osv-scanner.toml` in the repository. Exit 1 (advisories found) is success; 128 (nothing to scan) is success with no findings.
- semgrep stays detect-only (`not_run`): creep ships no local rules, and every other rule source is the network or the repository.
- Environment: only what creep sets. `PATH` is empty (no helper programs such as `git` or `go`), `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA` and `XDG_*` point at a fresh temporary home, `TMP`/`TEMP`/`TMPDIR` at a fresh temporary directory, and every proxy variable at `http://127.0.0.1:1` with `NO_PROXY` empty, so an HTTP attempt despite the offline flag fails instead of leaving the machine. `CREEP_API_KEY`, tokens and the operator's proxies are never passed. (Windows adds `SYSTEMROOT` itself.) This narrows, but cannot prove, the absence of network access: a tool could open raw sockets. The offline flags are the primary control, the environment the backstop.
- The working directory is that temporary directory, removed afterwards.
- Limits: 10 minutes per tool, a 64 MiB report, 10 000 findings. Standard output and error go to the null device.

**How output is read.** The report file is read up to the byte cap and decoded with `encoding/json` into closed structs that hold only the file, line and the tool's rule or advisory identifiers; matches, secrets, commits and authors are never decoded. Trailing data or a wrong shape is malformed. Each path must resolve inside the repository (`filepath.IsLocal` after `filepath.Rel`), be UTF-8 and at most 4096 bytes. Rule names and advisory IDs are hashed with the path and line into an opaque 24-digit key; the report finding is `<scanner>-<key>`, class `hardcoded_secret` or `vulnerable_dependency`, status `probable`, at the reported path and line. No tool text other than a checked path reaches the report, and the report escapes paths as it does for every repository string. Scanner findings go to the report only, never to the planner (invariant 3).

**Exit codes and completeness.** Scanner findings are findings like any other: they are rated `high` for the gate (`classSeverity`), so the default PR gate (`probable:critical`) does not trip on them. A scanner that was enabled and found but **failed** (did not start, non-success exit, timeout, report missing, malformed, over a cap, or a path outside the repository) evaluated nothing: its status is `failed`, the run is incomplete with reason `scanner_failed`, and `creep scan` exits 4 (ADR 0007, ADR 0009). `not_enabled`, `missing`, `refused` and `not_run` keep ADR 0010's meaning: listed, not evaluated, and not a gap.

**`creep doctor`.** It does not exist yet (#6). Asking a tool for its version executes it, so when #6 adds versions it must go through `scanrun` with the same rules.

## Consequences

- ADR 0010's line "the refusal rules above already decide which binary may run" is qualified: only the final-path rule here decides it.
- `internal/tools/budget` `execAllowed` gains `internal/scanrun` with its reason; any other package that imports `os/exec` still fails `make budget`.
- The report schema v1 `coverage.scanners[].status` enum gains `evaluated` and `failed`; Markdown, SARIF (a warning for `failed`) and the text summary say which classes a scanner evaluated.
- Tests: `internal/static/scanners_test.go` and `scanners_windows_test.go` (final path, links, cycles, `\\?\`), `internal/scanrun/run_test.go` with the test binary re-run as a fake scanner (findings, deduplication, malformed and missing report, byte and finding caps, timeout, non-zero exit, a path outside the repository, no key, proxy or `PATH` in the child, offline flags present; nothing starts for semgrep, osv-scanner without a database, a binary or database in the repository), `run_windows_test.go` (a junction into the repository, a `.cmd`), `internal/config/scanners_test.go` (project file may only remove), `internal/cli/scanners_run_test.go` (evaluated, failed, exit codes).
- A tool version whose flags differ (for example osv-scanner v1, which used `--experimental-offline`) exits non-zero and is reported `failed`, never run in an online mode.
- Running semgrep needs creep-shipped local rules: a new ADR.
