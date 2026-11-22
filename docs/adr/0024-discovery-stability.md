# ADR 0024: Discovery stability across model runs (`--stability N`)

- **Status:** Proposed
- **Date:** 2026-11-22
- **Deciders:** @Ludocius
- **Amends:** [ADR 0009](0009-scan-and-why-contract.md) (report v1 gains `stability` on a finding; a new flag), [ADR 0011](0011-estimate-and-stats.md) (`creep estimate` counts every sample), [ADR 0017](0017-language-agnostic-analysis.md) (union across samples)
- **Changes:** a new CLI flag `--stability <n>` (scan, estimate); report v1 additions (`stability` on a finding, `report.Stability`); `discover.Discoverer.Reruns`, `discover.Sink.SeenBy`, `discover.Result.Samples`, `discover.MaxSamples`; `calibrate.RecordStability`, `calibrate.ClassStability`, `calibrate.Calibration.Stability`; the `-s<k>` purpose label of sample k's calls in `egress.log` and the run-state cache key
- **Fitness function:** the row "Stability labels, never lowers, and replays exactly" of [architecture.md §9](../architecture.md#9-fitness-functions)

## Context

Models are non-deterministic: a finding one run reports can be missing from the next on the same commit (#37). ADR 0017 accepted this for live runs ("Nondeterministic live gate"). It is not the same as an intermittent bug: ADR 0020 already reports a PoC that verified in some of its runs as intermittent, which is a property of the app. A finding the model sees in some runs only is a property of the model, and says the model is at the edge of its ability for that class.

#37 asks for an optional `--stability N` that re-runs the analysis with the real model, labels findings seen in fewer than N runs `unstable discovery`, and feeds that back into calibration per class. Acceptance: the report tells unstable discovery from intermittent PoC, and stability never changes replay determinism.

Constraints:

- ADR 0017 is union only: model output never removes a candidate or lowers its risk. A second sample must not be a way to do either.
- Every call goes through the gateway, inside `budget.max_calls`, `budget.max_tokens` and `budget.max_seconds`; `creep estimate` must show the cost before the run (ADR 0011).
- JSON v1 changes additively only; there is no v2 (ADR 0009, #26 amendment; ADR 0022 added `fingerprint` and `suppression` the same way).
- The run-state cache keys a recording by the exact request. A live run serves a recorded answer for an identical request, so a naive re-run would get sample 1's answer back, and a replay could not tell samples apart.
- Standard library only.

## Options

What a sample repeats:

| Option | Pros | Cons |
|---|---|---|
| A. Each discovery batch and each reader hypothesis is sent N times, the same prompt each time | One walk, one redaction, one tripwire pass, one plan; the planner sees the union, so a candidate any sample names is planned | N times the egress |
| B. The whole scan N times, findings matched afterwards | Simple to explain | N walks, redactions, calibrations and reports; matching findings across separately numbered runs; a candidate one run lacks is not read in the others |

How sample k differs from sample 1 on the wire:

| Option | Pros | Cons |
|---|---|---|
| a. Its purpose is `<purpose>-s<k>`; sample 1 keeps its purpose | `egress.log` names every sample; the cache key holds the purpose, so each sample is its own call and its own recording; sample 1 is byte for byte what a run without the flag sends and records, so existing recordings replay unchanged | The model sees the same prompt N times, so a provider-side cache may answer identically (that is a stable answer, not a bug) |
| b. A per-sample nonce in the prompt | Defeats provider-side caching | Changes the prompts and their token-budget tests; a nonce the repository's text can see |

Where the stability goes in the report:

| Option | Pros | Cons |
|---|---|---|
| i. An optional `stability` object on a JSON finding (`runs`, `seen`, `unstable`), and the label in text, Markdown and SARIF | A JSON consumer can tell 2/3 from 3/3; additive under v1 like `fingerprint` | One more optional field a strict v0.2 reader does not know |
| ii. Text, Markdown and SARIF only, as the PoC rate (ADR 0020) | No JSON change | A CI consumer reading JSON cannot see the label at all |

## Decision

Options A, a and i. The maintainer rule that decided it: stability labels a finding and must never lower one, so it has to run inside the one union the planner already reads.

**Flag.** `--stability <n>` takes 1 to 5 (`discover.MaxSamples`, mirrored by `report.MaxStabilityRuns`; a test keeps them equal), default 1, only on `scan` and `estimate` (exit 2 elsewhere or out of range). It is a flag only: no config key, so the project file cannot set it.

**Samples.** Sample 1 is the scan's model; samples 2 to N are clients on the same send chain (run-state cache, `--stats`, gateway), each with its calls labelled `-s<k>` (`sampleSend`). Discovery sends every batch, with its canary, to every sample (`Discoverer.Reruns`); each reply is validated and its canary checked on its own; a reply that is invalid or misses the canary makes the batch's files `parse_failed` (exit 4) and its proposals still join the union; a file one sample failed stays failed whatever a later sample answers. A stopping error in any sample (budget, run_full, transport, the deadline) stops the model path as it does today. `Sink.SeenBy` has bit k set when sample k named the candidate; a tripwire hit sets every bit. The planner never reads it. The reader asks every planned hypothesis of every sample and keeps the riskiest answer: probable over undecided (inconclusive, invalid output) over discarded, so a sample can raise a finding and never lower it; a stopping failure in sample 1 is the finding's, as with one sample, and one in a later sample leaves the answers before it and gives the finding no stability.

**Label.** A probable finding every sample answered gets `Stability{Runs: N, Seen: s, Unstable: s < N}`, where a sample saw it when its discovery named the sink and its reader answered vulnerable. A finding a PoC later verifies keeps its label. `report.New` and `report.ReadJSON` refuse stability on a finding that is not probable or verified, runs outside 2 to 5, seen outside 0 to runs, and an `unstable` that does not match. Formats: text and `creep why` print `unstable discovery: seen in 2 of 3 runs` (or `stable discovery: ...`), Markdown puts it in the finding's notes, SARIF in the result's message and a `stability` property, JSON in the finding's `stability` object (published in `docs/schemas/report-v1.json`). An intermittent PoC reads `verified in 3/5 runs, intermittent`: the two never share a word, and a finding can carry both.

**Gate and exit code.** Unchanged. The gate reads statuses and an unstable discovery is still probable; stability never makes a run incomplete or complete. A run whose reruns hit the budget or the deadline is incomplete (exit 4) like any other.

**Calibration feedback.** After a live or `--record` scan with N ≥ 2, each calibrated class's labelled findings and unstable ones are added to a stability record beside the model's calibration (`calibrate.RecordStability`), in the user cache directory, signed with the per-user state secret like the calibration. Its key is the SHA-256 of the calibration's own key fields (model identity, client settings, seed, task set, prompt version) under the domain `creep discovery stability v1`, so it follows the calibration it notes and never answers as one. It is bounded: only calibrated classes, counts checked, and a class past 256 findings halves both counts. The record keeps the time of its first scan, so it expires `calibration.cache_days` after that however often later scans add to it. A record that is unsigned, planted, malformed, out of bounds, older than `calibration.cache_days` or from the future is not read and is started afresh; a record that cannot be written is a warning, never a failed scan. `Calibration.Stability` carries it and the calibration line names the classes with unstable discoveries (`· unstable discoveries: sqli 2/5`). It never changes the tier, a class's coverage or the plan.

**Replay.** The `-s<k>` label is in the cache key, so `--record` keeps one recording per sample and `--replay` serves each sample its own; the report a replay writes is byte for byte the recorded run's. The record never enters a report file; only the summary's calibration line names it, read as it stands in the user cache like the calibration's date. A replay never writes the stability record, so it neither reads its own effect nor changes what later scans read. A live run serves recordings like any run (ADR 0017 amendment 5): a second live `--stability` scan of the same tree reuses its samples' answers; `--record` asks the model again.

**Estimate.** `creep estimate --stability N` meters every sample's discovery and reader requests with the sample's label, so the calls, cached calls, tokens and the `budget.max_calls` and `budget.max_tokens` warnings count all of them, and it prints `stability: N runs`. The planner reserves one reader call per sample for each hypothesis (`planBudget`), so a stability scan plans only what `budget.max_tokens` pays for at N samples and skips the rest by budget, as `estimate` shows.

## Consequences

- A `--stability N` scan costs about N times the discovery and reader calls of a scan; the scan-start notice says discovery sends its files N times. PoC requests are not repeated (ADR 0020 already repeats the PoC itself).
- More samples can only add candidates and raise statuses, so a stability run can turn exit 0 into 1 or 4, never 1 or 4 into 0.
- A canary missed by any sample makes its batch incomplete, so a model that drifts makes more stability runs exit 4: fail closed, as for one sample.
- An injection that makes the model flap can make a real finding read `unstable`; the label never lowers its status or the gate, so it can only mislead a reader who trusts the label over the status (threat model R25).
- A strict JSON v0.2 reader (`additionalProperties: false`, `creep why` with `DisallowUnknownFields`) must take the current schema before it reads a report of a stability run, as for ADR 0022's fields.
- Tests: `internal/discover/stability_test.go:TestStabilityNeverDropsCandidates`, `TestRerunsSendEveryBatch`; `internal/report/stability_test.go:TestStabilityChecked`, `TestStabilityInFormats`, `TestReadJSONChecksStability`; `internal/calibrate/stability_test.go:TestStabilityFeedsCalibration`, `TestStabilityKeyFollowsCalibration`, `TestStabilityRecordBounded`, `TestStabilityRecordRefuses`, `TestStabilityRecordExpiresFromFirstScan`; `internal/cli/stability_test.go:TestStabilityLabelsFindings`, `TestStabilityNeverLowersRisk`, `TestStabilityReplayIsDeterministic`, `TestStabilityRespectsBudget`, `TestStabilityFlag`, `TestLabelStability`, `TestPlanBudgetCountsSamples`; the replay fixture `internal/cli/testdata/replay/stability` (`TestStabilityReaderReplay`; regenerate with `go test ./internal/cli -run TestStabilityReaderReplay -update`).
