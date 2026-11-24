# ADR 0032: `creep resume` continues an interrupted scan

- **Status:** Proposed (maintainer approval on the PR for #335)
- **Date:** 2026-11-24
- **Deciders:** @Ludocius
- **Amends:** [ADR 0009](0009-scan-and-why-contract.md) ("`resume` still fails closed; continuing a run needs per-step resume, a follow-up")
- **Changes:** the CLI contract of `creep resume <run>` (it runs the scan instead of exiting 2); the run state v1 (`events.jsonl`) gains an optional `header` on the start line and an optional `ms` on step lines, and a scan now records steps (`files:`, `tier:`, `cache:`); `egress.log` request lines gain an optional `reserve`; `gateway.OpenEgressLog` charges a reopened log's spend to the budget; `--stability`, `--changed`, `--baseline` and `--baseline-write` are accepted by `resume`. All additive: no field is removed or retyped, no new dependency, package, exit code or network path.

## Context

#335: `creep resume <run>` checked the run (lock, MAC, not ended) and exited 2, so a scan killed after an hour of model calls started again from zero. The JSONL run state (#8) already had step IDs, `Run.Done` and `Store.Resume`, but no scan recorded a step, and nothing tied a run to the settings it ran with.

The acceptance criteria: a resume is refused with nothing sent when the config, model, contract, endpoint, tier, mode, creep version, prompts or files differ; a finished step is never sent again and a cut one is sent again in full, with both attempts in `egress.log`; the budget and `budget.max_seconds` count what the run spent; the state MAC and `.creep/lock` hold; a resumed run's reports equal an uninterrupted run's with the same responses; a nightly resume never reuses a sandbox image.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Record each stage's output (discovery result, plan, verdicts) in the run state and restart from the first unfinished stage | Skips whole stages | A second serialization of every stage's types, kept in step with the pipeline; the state would hold model-derived data, not only IDs; a new code path that an uninterrupted run never takes, so "identical reports" rests on two implementations agreeing |
| B. Run the same pipeline again and serve every model call the run already finished from its recording in `.creep/cache` | One code path for scan and resume; the pipeline is deterministic given its replies (the discovery seed is a recording too), so the reports are the uninterrupted run's; the state gains only digests and IDs | Re-runs the local work (walk, redaction, planning); relies on the recordings still being in the cache |

## Decision

Option B, because a resumed run then executes exactly the code an uninterrupted run executes and only the transport differs, which is what makes "identical reports" hold by construction rather than by a second implementation.

**Steps.** Every scan records, as signed step lines, `files:<digest>` after the walk, `tier:<S|M|L>` after calibration, and `cache:<key digest>:<reply digest>` for every recorded model reply and the discovery seed once it is answered (128-bit digests of its cache key and of the reply the run got: no text). `session.respond` sits in front of `state.Store.Respond`: a `cache:` step the resumed run already finished is served from its recording only (`ModeReplay`), so it is never sent again, also in `--record` mode, where every other call is sent; and only when the recording's digest is the one the step recorded, since `.creep/cache` is shared and a later `--record` scan can rewrite an entry. A recording that is missing, invalid or rewritten refuses the resume: the run context is cancelled, nothing more is sent, the command exits 2 with no end line (the run stays as it was) and points to `creep scan`. The pipeline asks for every finished step before any step the run had not reached, so no new call was sent; the tool canary runs again, as on every resume. Only steps finished before this session are replay-only, so a planted cache file still cannot stop a new scan. A step that started but did not finish has no step line, so it is sent again in full.

**Header.** The start line carries a header of SHA-256 digests (never a value in clear): `version` (creep version and commit), `prompts` (discover, reader, calibrate and verify prompt versions), `contract`, `endpoint` (with `model.run`, `model.preset` and `model.env`), `model`, `mode` (pr or nightly), `options` (`--stability`, `--changed` list, `--baseline` and its entries, `--baseline-write`, `--recalibrate`, installed recipes) and `config` (the resolved config without `output` and `log`). Resume compares field by field, in that order, and refuses the first that differs, naming it and pointing to `creep scan`. A run without a header (started before this change) is refused. The state mode (live, `--record`, `--replay`) comes from the run; an explicit flag that contradicts it is refused.

**Order of checks.** Before any config is read: the run exists, is not locked, decodes with this user's MAC and has not ended. Before the model link opens: the header. After the walk, before the tool canary: the files digest (paths, what discovery can read of each file, and the walk's gaps). Before the canary: a run that recorded a tier reads its calibration from the cache only (`CacheOnly`) and is refused when it expired or the tier changed, since measuring again would send calls the run never made. So every refusal exits 2 with nothing sent, and leaves the run resumable.

**Budget.** `OpenEgressLog` on an existing log charges the budget with what the log records: one call per request line, and per call its reported tokens or, without a report (a call cut mid-flight), its reservation, now written as `reserve` on the request line. A request line without `reserve` charges the whole token limit; a line that does not decode is a torn write whose call was never sent. The resumed run appends to the same `egress.log`, so both attempts of a cut call are listed, and the report's data-handling section counts both.

**Deadline.** Step lines carry `ms`, the scan time spent when they finished (from the start of the deadline phase). A resumed run's deadline is `budget.max_seconds` less the largest recorded `ms`, and fires at once when nothing is left: the run is then cut as any run the deadline cut (reason `budget`, exit 4).

**Sandbox.** A resumed run opens its sandbox under `<run>-resume-<8 hex>`, never the run ID, so no container, network or image the killed run left is reused; the app is built again or verification is `unavailable`. `creep clean` removes what the killed run left.

## Consequences

- A killed scan no longer starts from zero: `creep resume <run>` (the folder name under `.creep/runs/`) with the same config and flags continues it, under the same gateway, redaction, canary, budget and exit codes (ADR 0007).
- Every scan reads each walked file once more for the files digest (at most `redact.MaxFileBytes` each) and writes one synced state line per model call.
- Tests: `cli.TestResumeMatchesUninterruptedRun` kills a run (runtime.Goexit, no end line) in calibration, discovery, the reader, record mode, a `--stability` sample and nightly mode, resumes it and compares stdout, exit code and every report with an uninterrupted run, and checks that only the cut call is sent twice; `TestResumeRefusesChangedRun` (each field, files, tier, expired calibration, state mode: exit 2, nothing sent, run still resumable); `TestResumeRefusesDamagedRun` (tampered, truncated, foreign); `TestResumeKeepsSpentDeadline`; `TestNightlyResumeRebuilds`; `TestResumedRunEnds`; `TestResumeRefusesRewrittenRecording` (a later `--record` scan over the shared cache, a removed cache); `TestResumeRefusesEditedBaseline`; `gateway.TestReopenedLogChargesBudget`, `TestReopenedLogKeepsBothAttempts`; `state.TestHeaderAndElapsedRoundTrip`, `TestHeaderValidation`, `TestTamperedHeaderRefused`. Threat model R18, R27.
- Residual risks: the deadline counts time up to the last finished step, so the time of the call that was cut is not counted (at most one call per sample, the pipeline is sequential); `egress.log` is not signed, so someone who can edit `.creep/runs/<run>/egress.log` can lower the spend a resume counts, as they could already edit the config the limits come from; `EndpointMaxTokens` is not restored (creep sets none); a run whose recordings were removed from `.creep/cache` or rewritten by a later scan cannot be resumed, only scanned again.
