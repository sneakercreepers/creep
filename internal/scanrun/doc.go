// Package scanrun runs the optional external scanners (gitleaks,
// osv-scanner) offline, with fixed arguments and no shell, and turns their
// reports into repository-relative findings.
//
// It exists because it is the one package in creep allowed to start another
// program (ADR 0013, the execAllowed entry in internal/tools/budget).
// Everything that makes that safe lives here:
//
//   - The binary is the final path static.DetectScanners resolved, checked
//     again with static.OutsideRepo right before the start, so a link or
//     junction into the repository or the working directory never runs. On
//     Windows only an .exe runs: a .bat or .cmd would start cmd.exe.
//   - Arguments are fixed per scanner; the repository path is the only
//     variable, passed as one argument. No shell parses anything.
//   - Only offline modes run: gitleaks on files only (--no-git) with creep's
//     own config, so a repository's .gitleaks.toml or .gitleaksignore cannot
//     hide a secret; osv-scanner with --offline against the user's local
//     database. semgrep needs rules creep does not ship, and osv-scanner
//     without a local database would go online, so both are not run.
//   - The process gets a minimal environment: an empty PATH, a fresh HOME
//     and TMP in a temporary directory that is also its working directory,
//     no tokens or keys, and every proxy variable pointed at a closed
//     loopback port, so a tool that tries HTTP despite its offline flag
//     fails instead of reaching the network.
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
