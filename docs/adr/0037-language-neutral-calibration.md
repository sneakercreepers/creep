# ADR 0037: Language-neutral calibration

- **Status:** Proposed
- **Date:** 2026-11-27
- **Deciders:** @Ludocius
- **Supersedes:** decision D5 of [ADR 0017](0017-language-agnostic-analysis.md) ("calibration templates stay Python and JS").
- **Amends:** [ADR 0036](0036-model-fitness-floor.md) (the planned classes are now every calibrated class; see its amendment), [ADR 0009](0009-scan-and-why-contract.md) (JSON v1 gains `coverage.calibration_scope`, SARIF a `creep/calibration-scope` note, additive), architecture §4 and §9.
- **Changes:** the calibration task set (templates, task prompt, `PromptVersion` 2, task-set hash) and so every cached calibration; the calibrated classes (`idor`, `missing_auth`, `prototype_pollution` leave, `template_injection`, `code_injection`, `insecure_deserialization` join); the coverage table lists the eight read classes only; every report states the calibration scope. No new flag, config key, dependency, exit code or network path.
- **Fitness function:** the row "Calibration is language-neutral (ADR 0037)" of [architecture.md §9](../architecture.md#9-fitness-functions).

## Context

#358: calibration measured the model's tier on 14 templates written in Python and JavaScript (`Language` = `python` | `javascript`) and applied that tier to every language discovery reads (ADR 0017 D5). On a Go, Java or Rust repository the "measured" tier was an assumption. Writing templates per language would bring back the per-language maintenance ADR 0017 removed from discovery, and the maintainer ruled it out (2026-11-26): creep must not carry a template set per language.

What the tier decides (step size, context per call, step cap) depends on abilities that are not about a language: keeping the closed schema, usable context (the context probe measures it), and following data from an input to a sink across a fragment, with and without sanitizing. The old set also measured three classes no scan reads (`idor`, `missing_auth`, `prototype_pollution`, ADR 0034 lists them as not looked for) and none of the three planned classes added since (`template_injection`, `code_injection`, `insecure_deserialization`, ADR 0036 consequences). And it cost 100 task calls: 20 minutes on a CPU in #367.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Templates per language discovery reads | The tier is measured on the repository's language | One template set per language, forever; a new language in the inventory needs calibration work; mixed repositories need a rule for which tier wins; the maintainer ruled it out |
| B. Keep Python and JavaScript, label the tier "measured on Python and JavaScript" | No change | The tier still reads as a rating of the scanned language; the planned classes stay unmeasured |
| C. One language-neutral pseudocode task set over the classes a scan reads | One set, written once; no language type, field or path; same tier on every repository; covers every planned class; fewer calls | Pseudocode is not what the reader sees on a scan, so the tier says nothing about knowledge of a language; that has to be said and protected elsewhere |

## Decision

Option C.

**The task set.** Sixteen templates under `internal/calibrate/templates/`, two for each class a scan can plan and read: `sqli`, `nosql_injection`, `command_injection`, `path_traversal`, `ssrf`, `template_injection`, `code_injection`, `insecure_deserialization`. Each is a short program in one minimal pseudocode, `handler f(request): input → transform → sink`, with a vulnerable variant and a safe twin. The task prompt (`prompts/task.txt`) defines the builtins whose meaning decides the label (what `request.*`, `shell`, `run_process`, `templates.render`, `eval`, `make_function`, `deserialize_object` and `parse_json` do) and names the eight classes. Mutation is unchanged: identifier renames from each template's pools and neutral filler lines, drawn from a PCG source seeded with the seed. Loading refuses a slot value that is a pseudocode keyword or builtin, so a rename can never turn a handler into a sink. `template.json` and `fillers.json` move to `version` 2 with no language field; a v1 file is refused.

**Size.** `TaskCount` is 64: 8 tasks per class, 4 vulnerable and 4 safe twins. That keeps the per-class bounds the smallest classes already had (7 of 8 for L, 5 of 8 for M) and the fitness floor's 64 planned tasks, and cuts the task calls from 100 to 64 (see Cost).

**No language anywhere.** `internal/calibrate` has no `Language` type, field or branch; `TestTaskSetNamesNoLanguage` fails if a language, runtime or framework name appears in a template, a filler, the task prompt or a generated task. Adding a language to discovery never touches calibration. No report names a language as measured.

**What the tier means.** The tier measures structured output, usable context, tool calling and data-flow reasoning on neutral tasks, not knowledge of the repository's languages. Every report says so: the text summary prints `calibration scope: …` under the calibration line, Markdown a sentence under the class table, SARIF a `creep/calibration-scope` note, JSON v1 `coverage.calibration_scope: "language_neutral"` (additive; a v1 report without it still reads). Language competence stays protected by design, not by a gate: discovery is union only, the model never removes or lowers a candidate, every batch carries the canary, and anything not read in full exits 4 (ADR 0017). `creep bench` keeps reporting quality per language as optional data and never gates a scan.

**Cache.** The key is unchanged in shape (model identity, client settings, seed, task-set hash, `PromptVersion`). The new templates change the task-set hash and the new prompt bumps `PromptVersion` to 2, so every v0.5 entry is a miss and the model is measured again once; its result signed under the new key still names the old task set and is refused (`TestV05CacheNotServed`). Nothing from the scanned repository is in the key, so the same model is served the same entry on every repository (`TestCalibrationIgnoresRepositoryLanguages`).

**Coverage.** The class table lists the eight read classes, all calibrated. `idor`, `missing_auth` and `prototype_pollution` leave it: they are not read by any scan and are already in every report's not-looked-for list (ADR 0034).

## Cost

Measured offline with an oracle model on seed 1 (the CLI's seed), as bytes of request payload, which bound tokens from above:

| | Old set (v0.5) | Neutral set |
|---|---|---|
| Task calls | 100 | 64 |
| Task payload bytes | 164,724 | 121,183 (−26%) |
| All calls (tasks, 3 tool, 3 context probes) | 106 | 70 (−34%) |
| Calls in the tier-M replay fixture (one retry) | 107 | 71 |

The task prompt grew to define the builtins (536 to 1,022 bytes, under the 1,024-byte cap), and each task is shorter. Probes are unchanged. On #367's CPU (about 11 s per call) that is about 6.6 minutes fewer per calibration.

## Consequences

- Every model is calibrated again once after the upgrade.
- A tier earned on Python and JavaScript may differ from the neutral one; reports name what was measured.
- Replay fixtures `calibrate/testdata/replay/seed1_tier_{s,m,l}.json` are synthesized (one per tier) and owe a live recording; a live neutral calibration of a real model replaces them.
- Tests: `calibrate/neutral_test.go` (`TestTaskSetNamesNoLanguage`, `TestSafeTwinsCleanInEveryClass`, `TestEmbeddedCatalogCoversEveryClass`), `templates_test.go` (v1 and language fields refused, builtins refused as slot values), `tier_test.go` (`TestPlannedClassesAreCalibrated`, the new classes at the floors), `run_test.go` (`TestRunReplayIsDeterministic` over S, M and L, `TestFixturesCoverEveryTier`), `cache_key_test.go:TestV05CacheNotServed`, `cli/calneutral_test.go:TestCalibrationIgnoresRepositoryLanguages`, `report/calibscope_test.go:TestCalibrationScopeInEveryFormat`.
