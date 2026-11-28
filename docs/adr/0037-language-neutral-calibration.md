# ADR 0037: Language-neutral calibration

- **Status:** Accepted (maintainer, 2026-11-27)
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

**The task set.** Sixteen templates under `internal/calibrate/templates/`, two for each class a scan can plan and read: `sqli`, `nosql_injection`, `command_injection`, `path_traversal`, `ssrf`, `template_injection`, `code_injection`, `insecure_deserialization`. Each is a short program in one minimal pseudocode, `handler f(request): input → transform → sink`, with a vulnerable variant and a safe twin. The task prompt (`prompts/task.txt`) defines every builtin under `The only builtins:`, each call and each field the pseudocode may use, and names the eight classes. That list is the single source: loading refuses a slot value that is a keyword or any part of a builtin, and `TestTaskSetUsesOnlyPromptBuiltins` fails a generated task that calls, or reads a field, the prompt does not define, so an API of a real language (`cursor.execute`, `request.args.get`, `os.system`) cannot enter the set. Mutation is unchanged: identifier renames from each template's pools and neutral filler lines, drawn from a PCG source seeded with the seed. A rename can therefore never turn a handler into a sink. `template.json` and `fillers.json` move to `version` 2 with no language field; a v1 file is refused.

**Size.** `TaskCount` is 64: 8 tasks per class, 4 vulnerable and 4 safe twins. That keeps the per-class bounds the smallest classes already had (7 of 8 for L, 5 of 8 for M) and the fitness floor's 64 planned tasks, and cuts the task calls from 100 to 64 (see Cost).

**Per-class scores are indicative.** The Wilson bounds treat every task as independent, but a class's 8 tasks come from 2 templates, 4 renamed pairs each, so they are correlated and a per-class interval is narrower than the evidence. A per-class score is reported as data, not a measurement to act on: the decisions are the fitness floor over all 64 tasks and the tier, where the per-class minimum works only as a coarse screen against a model that fails one class outright.

**No language anywhere.** `internal/calibrate` has no `Language` type, field or branch; The code is held to the builtin allowlist above; `TestTaskSetNamesNoLanguage` also fails if a language, runtime or framework name appears in the prose of a template, the task prompt or a generated task.

**Safe twins use their class's mitigation.** Both twins of a template call the same dangerous builtin on the sink line (`shell`, `eval`, `make_function`, `deserialize_object`, `templates.render`, `db.query`, `store.*`, `read_file`/`write_file`, `http_*`), so a model cannot score by spotting a name; the twins differ only by the defense (`TestBothTwinsCallTheClassSink`). `TestSafeTwinsUseTheirClassMitigation` checks each safe twin for the specific defense of its class, and each vulnerable twin for its absence: a bound `?` parameter or an allowlisted literal (sqli), `to_string` on every caller value in a filter (nosql_injection), a fixed command whose one caller value is allowlisted or pattern-checked against options and shell syntax (command_injection), a canonical path checked against its root with the trailing slash or a name pattern that refuses `..` and separators (path_traversal), a fixed https scheme and a literal or allowlisted host (ssrf), a literal template (template_injection), code text that is an allowlisted literal or matches an arithmetic-only pattern (code_injection), a `deserialize_object` type list of plain data only (insecure_deserialization). Patterns are compiled and run against attack strings. `TestMitigationChecksRefuseWeakenedGuards` weakens each twin (the wrong refusal, a missing anchor, a prefix without its slash, a reassignment after the guard) and expects every weakening to fail. Adding a language to discovery never touches calibration. No report names a language as measured.

**What the tier means.** The tier measures structured output, usable context, tool calling and data-flow reasoning on neutral tasks, not knowledge of the repository's languages. Every report says so: the text summary prints `calibration scope: …` under the calibration line, Markdown a sentence under the class table, SARIF a `creep/calibration-scope` note, JSON v1 `coverage.calibration_scope: "language_neutral"` (additive; a v1 report without it still reads). Language competence stays protected by design, not by a gate: discovery is union only, the model never removes or lowers a candidate, every batch carries the canary, and anything not read in full exits 4 (ADR 0017). `creep bench` keeps reporting quality per language as optional data and never gates a scan.

**Cache.** The key is unchanged in shape (model identity, client settings, seed, task-set hash, `PromptVersion`). The new templates change the task-set hash and the new prompt bumps `PromptVersion` to 2, so every v0.5 entry is a miss and the model is measured again once; its result signed under the new key still names the old task set and is refused (`TestV05CacheNotServed`). Nothing from the scanned repository is in the key, so the same model is served the same entry on every repository (`TestCalibrationIgnoresRepositoryLanguages`).

**Coverage.** The class table lists the eight read classes, all calibrated. `idor`, `missing_auth` and `prototype_pollution` leave it: they are not read by any scan and are already in every report's not-looked-for list (ADR 0034).

## Cost

Measured offline with an oracle model on seed 1 (the CLI's seed), as bytes of request payload, which bound tokens from above:

| | Old set (v0.5) | Neutral set |
|---|---|---|
| Task calls | 100 | 64 |
| Task payload bytes | 164,724 | 161,915 (−2%) |
| All calls (tasks, 3 tool, 3 context probes) | 106 | 70 (−34%) |
| Calls in the tier-M replay fixture (one retry) | 107 | 71 |

The task prompt grew to define every builtin (536 to 1,637 bytes), so the system-prompt cap in `TestSystemPrompts` rises from 1,024 to 2,048 bytes and the task-call token budget from 2,000 to 2,600; each task is shorter, which leaves the bytes about even. Probes are unchanged. Time on a local model is dominated by calls: on #367's CPU (about 11 s per call) 36 fewer calls are about 6.6 minutes fewer per calibration.

## Consequences

- Every model is calibrated again once after the upgrade.
- A tier earned on Python and JavaScript may differ from the neutral one; reports name what was measured.
- Replay fixtures `calibrate/testdata/replay/seed1_tier_{s,m,l}.json` are synthesized (one per tier) and owe a live recording; a live neutral calibration of a real model replaces them.
- Tests: `calibrate/neutral_test.go` (`TestTaskSetNamesNoLanguage`, `TestSafeTwinsCleanInEveryClass`, `TestEmbeddedCatalogCoversEveryClass`), `builtins_test.go` (`TestTaskSetUsesOnlyPromptBuiltins`, `TestBuiltinAllowlistCatchesLanguageAPIs`), `mitigation_test.go` (`TestBothTwinsCallTheClassSink`, `TestSafeTwinsUseTheirClassMitigation`, `TestMitigationChecksRefuseWeakenedGuards`), `templates_test.go` (v1 and language fields refused, builtins refused as slot values), `tier_test.go` (`TestPlannedClassesAreCalibrated`, the new classes at the floors), `run_test.go` (`TestRunReplayIsDeterministic` over S, M and L, `TestFixturesCoverEveryTier`), `cache_key_test.go:TestV05CacheNotServed`, `cli/calneutral_test.go:TestCalibrationIgnoresRepositoryLanguages`, `report/calibscope_test.go:TestCalibrationScopeInEveryFormat`.
