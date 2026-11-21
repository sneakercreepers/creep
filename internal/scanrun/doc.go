// Package scanrun runs the optional external scanners (gitleaks,
// osv-scanner) offline, with fixed arguments and no shell, and turns their
// reports into repository-relative findings.
//
// It exists because it is the one package in creep allowed to start a
// scanner (ADR 0013, the execAllowedExact entry in internal/tools/budget;
// the gateway runs model CLIs and the sandbox the container runtime).
// Everything that makes that safe lives here:
//
//   - The binary is the final path repofile.DetectScanners resolved, checked
//     again with repofile.OutsideRepo right before the start, so a link or
//     junction into the repository or the working directory never runs. On
//     Windows only an .exe runs: a .bat or .cmd would start cmd.exe.
//   - Arguments are fixed per scanner; the repository path is the only
//     variable, passed as one argument. No shell parses anything.
//   - Only offline modes run: gitleaks on files only (--no-git) with creep's
//     own config, so a repository's .gitleaks.toml cannot hide a secret;
//     osv-scanner with --offline and --no-ignore against the user's local
//     database. semgrep needs rules creep does not ship, and osv-scanner
//     without a usable local database would go online or match nothing, so
//     both are not run.
//   - The repository cannot suppress a finding (#226). gitleaks always
//     reads <source>/.gitleaksignore, so when the repository root holds one
//     it is left out, never honored: gitleaks runs once per other root
//     entry (at most 256; links and .git skipped), the result says the file
//     was skipped and the CLI prints that. A root directory holding its own
//     .gitleaksignore, or more entries, leaves no clean source: failed,
//     unstarted, the run incomplete. Fail toward visibility: a run either
//     shows every finding or is incomplete.
//   - osv-scanner matches a lockfile only against its ecosystem's database
//     and reports nothing on a miss, so every lockfile ecosystem in the
//     repository (lockfileEcosystems, a walk that follows no link) needs a
//     non-empty <db>/osv-scanner/<ecosystem>/all.zip; otherwise it is
//     failed (missing_ecosystem_db) and not started (#226). A lockfile
//     format the map lacks is the residual.
//   - The process gets a minimal environment: an empty PATH, a fresh HOME
//     and TMP in a temporary directory that is also its working directory,
//     no tokens or keys, and every proxy variable pointed at a closed
//     loopback port, so a tool that tries HTTP despite its offline flag
//     fails instead of reaching the network.
//   - On timeout the whole tree dies. Unix kills the scanner's process
//     group. Windows has no job object without x/sys or unsafe (no new
//     dependency, invariant 6), so the system's taskkill.exe /T /F, by
//     absolute path under SystemRoot with fixed arguments and no shell,
//     kills the tree while the scanner is alive (its handle pins the
//     process ID), then the scanner itself is killed (#226). A helper whose
//     parent already exited is no longer in the tree (residual).
//   - A timeout, a byte cap on the report and a cap on findings bound each
//     run. The report is decoded into closed structs; paths must lie inside
//     the repository, and rule names, advisories and matches are hashed into
//     an opaque key, so no tool text other than a checked path leaves.
//
// A scanner that fails in any way (start, exit status, timeout, oversized or
// malformed report, a path outside the repository) evaluated nothing, and
// the caller marks the run incomplete. Findings never reach the planner
// (invariant 3); they go to the report only.
package scanrun
