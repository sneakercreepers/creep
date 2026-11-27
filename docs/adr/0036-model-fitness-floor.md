# ADR 0036: Refuse a model calibration finds unfit, unless the user overrides

- **Status:** Accepted (maintainer, 2026-11-27)
- **Date:** 2026-11-27
- **Deciders:** @Ludocius
- **Fitness function:** the row "An unfit model is refused or every finding is labeled" of [architecture.md §9](../architecture.md#9-fitness-functions)
- **Changes:** exit code 3 gains a reason (a model the fitness floor refuses); a new CLI flag `--allow-unfit-model` (`scan`, `resume`); JSON v1 and SARIF gain an optional `unreliable_model` on a finding, Markdown and the text summary print the label; the calibration result (cache entry) gains `fitness` and per-class `safe_twins` and `safe_flagged`; the tier rules read only the classes the planner can plan; `creep bench --recalibrate` adds an optional `calibration` object to the bench results v1; `--stats` prints a `calibration:` line. All additive: no exit code, field or flag is removed or retyped, no new dependency, package or network path.

## Context

#363: calibration picks a tier but never says a model is unfit. `assignTier` falls back to S, and a failed structured check only blocks M and L, so a model at or below chance still scans and reports `probable` findings. In the local run of #367, `qwen2.5-coder:1.5b` on a CPU calibrated tier S in 20 min 18 s (108 calls, ~50k tokens in) and then reported as many findings on every safe twin as on its vulnerable twin; in nightly 45606731046 it answered `vulnerable` on 122 of 128 reader calls. A report from such a model looks like a report from a good one.

The tier rule also counted all eight calibrated classes, while the planner plans only five (`sqli`, `nosql_injection`, `command_injection`, `path_traversal`, `ssrf`: the classes a discover sink kind maps to). A weak `prototype_pollution` score held a model at S although no prototype-pollution finding is ever planned (#358 will replace the task set; this change keeps to the tier rule).

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Keep scanning; label every finding of a low-scoring model | Never blocks a user | The default output of a useless model is still a list of `probable` findings that a CI gate acts on |
| B. Refuse an unfit model with exit 3; an explicit flag scans anyway and labels every finding | A useless model cannot produce a report by default; the user who knows better can still scan, and every consumer of the report sees the label | One more refusal path, and a flag that must not reach the untrusted layer |
| C. A new exit code for "model unfit" | CI can tell it apart | Exit codes are a stable contract (ADR 0007); 3 already means "model failure", and the message carries the reason |

## Decision

Option B, because a model that cannot tell a sink from its safe twin makes every finding noise, and noise a gate acts on is worse than no report.

**The floor**, over the planned classes' tasks only (64 of the 100 for every seed, 32 of them safe twins), checked after every calibration and stored with it:

1. *Above chance.* The 95% Wilson lower bound of the score must reach 1/2. Calibration's tasks are half vulnerable and half their safe twins in every class, so a model that ignores the code (always "vulnerable", always "safe", a coin) scores 1/2; the lower bound, compared in exact rationals like the tier rules, asks for evidence it does better: 40 of 64 right (lower 0.503), where 39 is refused. Reason `below_chance`.
2. *Does not flag most safe twins.* At most half of the planned safe twins may be answered other than "safe" (a finding of any class, or no valid answer). This is a plain majority, not an interval: "most" is a count, and the first floor already demands confidence. A model that is right on every vulnerable task and flags 17 of 32 twins passes the first floor (47 of 64) and is refused here. Reason `flags_safe_twins`.

A result that does not score every calibrated class is unfit, so a zero value is never fit.

**Refusal.** `creep scan`, `creep resume` and `creep recipe test` stop after calibration with exit 3 and `model unfit (<reason>): N of 64 tasks in the planned classes right (95% lower bound L, needs at least 0.5, chance); F of S safe twins not called safe (needs at most half)`, before any repository file is sent and with no report. `creep mcp` is refused the same way (its calibration is cache-only and it takes no override).

**Override.** `--allow-unfit-model`, a flag only: there is no config key, so neither the project file nor any other layer can set it, and `scan` and `resume` are the only commands that accept it (any other, including `mcp`, exits 2). With it the scan warns on stderr, the calibration line ends `UNFIT (<reason>, …): findings labeled unreliable_model`, and every finding the model decided or left undecided carries `unreliable_model` in the text summary, `creep why`, Markdown, SARIF (message and `properties.unreliable_model`) and JSON v1 (`"unreliable_model": true`, absent otherwise). Findings from gitleaks and osv-scanner are not the model's and are not labeled. The label never changes a status or the gate. The resume header does not carry the flag: a run gets past calibration only fit or with the flag, and a resume without it is refused by the floor again.

**Cache.** The calibration entry records `fitness` and, per class, `safe_twins` and `safe_flagged`. A cached entry is used only when its counts fit inside each other and the current rules give it the fitness and tier it records, so a cached unfit model is refused with no model call, and an entry from before this change (no fitness) is a miss and is measured again.

**Tier rule.** Both bounds (overall and per class) read only the planned classes. Over the 64 planned tasks L needs 55 right and M 44. The other classes are still measured and listed in the report's coverage.

**Cost.** `--stats` prints `calibration: N requests (M sent), I tokens in, O out, T` (no calls when cached). `creep bench --recalibrate` (live only; `--replay` refuses it, the published fixture has no calibration) runs one real calibration under its own `budget.max_seconds` before the corpus and adds `calibration` (`calls`, `input_tokens`, `output_tokens`, `seconds`, `tier`, `fit`, `unfit_reason`) to the results; it never reads or writes the calibration cache, and the fixture keeps corpus replies only. The nightly local bench runs it on the pinned Ollama model. `creep estimate` keeps its assumed 5 s per call for a hosted model and also prints the 11 s per call measured on a local CPU model (#367).

## Consequences

- A small local model that cannot do the job now fails a first scan with exit 3 after calibration instead of producing a report; the message gives the numbers and the flag. README and the exit-code table say so.
- Consumers of JSON v1 and SARIF may see `unreliable_model`; v1 stays additive, so readers that ignore unknown fields are unaffected.
- Cached calibrations from earlier versions are measured again once, which costs a calibration per model (about 20 minutes on a CPU, seconds on a hosted model).
- Tests: `calibrate/fitness_test.go:TestUnfitModelRefused` (a replayed model that answers "vulnerable" to every task is refused, and again from the cache with no call), `TestAssessFitness` (both floors at their boundaries, unplanned classes ignored), `cli/unfit_test.go:TestScanRefusesUnfitModel` (exit 3, no call past the floor, no report; no config key; refused on `estimate` and `mcp`), `TestAllowUnfitModelLabelsFindings` (label in every format), `report/unreliable_test.go`, cache-forging cases in `TestUntrustedCacheRecalibrates`, `TestPlannedClassesMatchPlannerKinds`, `cli/benchcal_test.go`, `tools/benchgate:TestNightlyBenchMeasuresCalibration`.
- `template_injection`, `code_injection` and `insecure_deserialization` (the last two since #369) are planned but have no calibration tasks, so neither the tier nor the floor can read them; their findings carry the `unreliable_model` label like any other when the floor is overridden, and `cli/plannermap_test.go:TestPlannedClassesMatchPlannerKinds` fails on any other planned class that is neither calibrated nor listed uncalibrated. #358 replaces the task set and covers adding them; `PlannedClasses` and the floor carry over, and it may stop measuring `idor` and `missing_auth`.
