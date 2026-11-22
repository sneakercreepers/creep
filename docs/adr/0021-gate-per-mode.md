# ADR 0021: A gate per scan mode, and a nightly scan without verification

- **Status:** Proposed
- **Date:** 2026-11-21
- **Deciders:** @Ludocius
- **Amends:** [ADR 0009](0009-scan-and-why-contract.md) (which gate a scan reads, and when the sandbox runs), [ADR 0020](0020-poc-repetitions-and-bundle.md) (PoCs run only in a nightly scan)
- **Changes:** the CLI contract (`--mode pr|nightly`, a `gate:` line on stderr, two rows `mode` and `gate` after the keys in `creep config explain`); the meaning of exit code 1 (the gate of the scan's mode, not always `gates.pr`)
- **Fitness function:** the row "The scanned repository cannot loosen the gate that judges it" of [architecture.md §9](../architecture.md#9-fitness-functions)

## Context

#28 asks for a gate per mode: `gates.pr` (`probable:critical`) for pull request scans, which have no sandbox, and `gates.nightly` (`verified:high`) for nightly scans, which verify. Both keys exist since #2, but every scan read `gates.pr`, and with `sandbox.enabled` every scan built the app and ran PoCs (#23, #25). The acceptance criteria: a PR scan never waits for verified findings, and the policy's `limits` still apply per mode.

Constraints:

- A mode picks which gate judges the run. The project file comes from the scanned repository, so the repository must not pick a weaker gate, through the mode or through a gate value (#61, #62, #249).
- `verified:high` reads only verified findings. When the sandbox is off or unavailable nothing is verified, so a nightly scan would exit 0 on every finding: a nightly run that cannot verify must not pass silently.
- ADR 0009 (#23 amendment) keeps the verification outcome out of the exit code and out of incompleteness: a broken Dockerfile must not force exit 4, and JSON v1 gains no field or reason (maintainer, #278).

## Options

Where the mode comes from:

| Option | Pros | Cons |
|---|---|---|
| A. A config key `mode` | `config explain` shows it like any key | The project file would need a new forbidden key; a policy default would make every local run nightly |
| B. `--mode`, else the CI event: nightly for a GitHub Actions `schedule` event, else pr | The repository cannot set it; a scheduled GitHub workflow needs no flag | Other CI systems pass `--mode nightly` |

What a nightly scan does when verification did not run:

| Option | Pros | Cons |
|---|---|---|
| a. Exit 0 as the gate says | No change | Every unverified finding passes; a repository breaks its own build to pass |
| b. Incomplete (exit 4) with a new reason | Says the run did not do its whole job | A new incomplete reason in JSON v1; exit 4 even with no finding at all; hides the verdict on the findings; a broken Dockerfile forces it (ADR 0009) |
| c. Exit 2 before the scan when the sandbox is off | Fails before any model call | The sandbox can also fail after the analysis (no runtime, build refused, no port), so c still needs a or b there |
| d. Read the gate as `probable:<severity>` (the gate failure path) | Every finding at the gate's severity still fails the run, verified or not; no report change; a broken build gains nothing | A nightly run without a sandbox fails on probable findings, so it is noisier than one that verified |

## Decision

Option B and option d.

**Mode.** `--mode pr|nightly` (exit 2 for any other value, also an empty one). Without the flag, a run with `GITHUB_ACTIONS=true` and `GITHUB_EVENT_NAME=schedule` is nightly, anything else is pr. The mode is never a config key, so neither the project file nor any other file can set it (`unknown key "mode"`, exit 2). GitHub refuses a step that writes `GITHUB_*` to `$GITHUB_ENV`, so a build step of the repository cannot turn a pull request run into a nightly one. Each mode reads its own key, `gates.pr` or `gates.nightly`, with the existing rules: the project file may only make either stricter than the built-in, policy-limit and inherited gate, and `checkLimits` floors both keys by the policy's `limits` whatever the mode, so a limit applies to the mode that reads it.

**PR mode never waits.** A pr scan never builds the app or runs a PoC, even with `sandbox.enabled`; it prints `verification: pr mode builds no app and runs no PoC, so findings stay probable; --mode nightly verifies` and its gate reads probable findings. Its verdict is the same as before #23: `gates.pr` reads probable and verified alike.

**Nightly mode verifies, and fails closed without it.** A nightly scan builds and runs PoCs as ADR 0020 says. When verification did not try every finding it should have, the nightly gate is read with its status raised to probable (`config.UnverifiedGate`: `verified:high` becomes `probable:high`; a probable gate and `none` are unchanged; the result is never looser than the gate). That is the case when `sandbox.enabled` is false, when verification is `unavailable` for any reason, or when a PoC candidate got no completed run (`PoCSummary.NotRun > 0`: the 16-PoC cap, no valid PoC, a model or sandbox error, the deadline). A finding at the gate's severity then fails the run with exit 1, and the gate line says why: `gate: nightly mode (flag --mode): gates.nightly "verified:high" (default) read as "probable:high": verification unavailable (no_runtime)`. A run with no finding at that severity exits 0: nothing unverified reached the gate. The verification outcome still never makes a run incomplete and JSON v1 does not change; only the gate a nightly scan reads moves.

**What the scan prints.** Every scan prints one `gate:` line on stderr: the mode, how it was chosen (`flag --mode`, `GitHub Actions schedule event`, `default`), the key, its value and the layer that set it. `creep config explain` adds two rows after the keys: `mode` with its source, and `gate` with the key and layer (`gates.nightly, user "~/.creep/config.yaml"`), in text and JSON.

## Consequences

- **Residual: the nightly gate reads verified findings only when verification ran.** A finding whose PoC ran all its runs and never verified stays probable (ADR 0020), and the nightly gate does not read it; so does a probable finding of a class with no PoC template (`ssrf`, `command_injection`, `nosql_injection`) and a scanner finding. The scanned repository builds the app, so on the scheduled branch it can make every PoC fail and pass the nightly gate on probable findings. The PR gate judged those changes at probable when they were merged, and the report lists each such finding as probable (`not reproduced` in the PoC summary). An operator who wants the nightly scan to fail on probable findings sets `gates.nightly: probable:high` in the user file or the policy.
- A local `creep scan` is pr: it no longer builds the app. `creep scan --mode nightly` verifies locally. v0.2 is not released, so no released behavior changes; `creep doctor` says so.
- A nightly run without a sandbox, or whose sandbox fails, is noisier, never quieter: it fails on probable findings at the gate's severity.
- Other CI systems (GitLab, Azure, Jenkins) do not switch to nightly on their own; their scheduled job passes `--mode nightly`. Adding another provider's schedule variable needs a check that a build step cannot set it, as for `GITHUB_*`.
- The README has a nightly workflow example (scheduled, `contents: read`, actions pinned by SHA); the wiki page "Nightly scan" mirrors it.
- Tests: `internal/config/mode_test.go:TestChooseMode`, `TestUnverifiedGateNeverLoosens`, `TestProjectCannotLoosenTheModeGate`, `TestModeGateHonorsLimits`, `TestExplainMode`; `internal/cli/gatemode_test.go:TestPRModeNeverWaitsForVerification`, `TestNightlyNeverPassesUnverified`, `TestProjectFileCannotLoosenNightlyGate`, `TestPolicyLimitsApplyPerMode`, `TestExplainShowsModeGate`, `TestInvalidModeIsUsageError`; `internal/cli/poc_test.go:TestPoCRateDecidesStatus` (the nightly exit code per PoC outcome), `TestZeroRunsStayProbable`. The protection tests run in `make protections`.
