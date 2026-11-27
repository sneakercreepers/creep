# ADR 0034: Classes creep does not look for, and code eval and deserialization as their own classes

- **Status:** Accepted (maintainer, 2026-11-27)
- **Date:** 2026-11-27
- **Deciders:** @Ludocius
- **Changes:** the report contract gains a fixed list of the classes no scan looks for, in every format (JSON v1 `coverage.not_looked_for`, additive); SARIF rules gain a CWE tag; discovery, the planner and the reader gain two sink kinds and two classes (`code_eval` → `code_injection`, `deserialize` → `insecure_deserialization`); discovery's `PromptVersion` goes to 2. No dependency, flag, exit code or config key. Amends ADR 0009 (report classes) and ADR 0017 (the tripwire's kind column).
- **Fitness function:** the row "Coverage never implies a class creep does not look for" of [architecture.md §9](../architecture.md#9-fitness-functions): `internal/cli/notlookedfor_test.go` (`TestScanOfCFileSaysMemorySafetyIsNotLookedFor` against `testdata/scan_c.golden`, `TestEvalAndDeserializationAreNotCommandInjection`, `TestNotLookedForAgreesWithCoverage`) and `internal/report/notlookedfor_test.go` (`TestReadmeListsNotLookedFor`, `TestNewAlwaysListsNotLookedFor`)
- **Threat model:** no trust boundary changes; the two kinds are closed enums the model may name, at the same planner severity as `shell`

## Context

#365. The planner had six sink kinds (`sql`, `nosql`, `shell`, `file`, `http_client`, `template`). Code evaluated from a string and objects decoded from bytes were tripwire rows of kind `shell`, so an `eval(request.args["e"])` or a `pickle.loads(request.data)` was reported as `command_injection` (CWE-78), the wrong class and the wrong CWE for the fix a reader looks up. Coverage listed only classes creep looks for, so a C or C++ repository could end complete with every listed class `covered` and exit 0 while its main bug class, memory safety, was never searched. Nothing in the report or the README said so.

## Options

**Code eval and deserialization.**

| Option | Pros | Cons |
|---|---|---|
| A. Keep `shell`, map the CWE at report time | No new enum | The report cannot tell an `eval` from a `system`: discovery drops the signature and keeps only the kind, so a CWE mapping would need the tripwire row back in the report, a text path the planner layer must not carry. It is not smaller, only hidden |
| **B. Two sink kinds and two classes, language-neutral** | Each finding has its real class and CWE; the planner stays IDs and enums; the tripwire rows only change their kind column | Discovery's prompts and schema name two more kinds, so its `PromptVersion` and the discovery replay fixtures change; the reader gets two classes calibration does not measure |

**Memory safety and XXE.**

| Option | Pros | Cons |
|---|---|---|
| C. Make them classes now | Searched | Memory safety is not a source-to-sink flow the reader checks in one slice: an overflow depends on sizes and lifetimes across calls, and a lexical `strcpy(` row would flood every C file with candidates the reader cannot judge, at full risk (ADR 0017). XXE depends on parser defaults per library and version; a tripwire on `parse(` cannot tell a safe default from an unsafe one. Neither has a calibration task, a bench case or a PoC template |
| **D. List them as not looked for, with every other class creep has no sink kind for** | Honest today, in every format, at no model cost; a class leaves the list in the same change that gives it a sink kind and a reader class | They are still not searched |

## Decision

Options B and D.

1. **Two kinds, two classes.** Discovery (`discover.SinkCodeEval` `code_eval`, `discover.SinkDeserialize` `deserialize`), the planner (`planner.SinkCodeEval`, `planner.SinkDeserialize`; `planner.ClassCodeInjection`, `planner.ClassDeserialization`) and the reader (`code_injection`, `insecure_deserialization`) each gain them, mapped by explicit switch (`internal/cli/plannermap.go`). The tripwire's eval and deserialization rows take the new kinds; no row is added or removed and no row names a language. The planner ranks both with `shell` (they all run attacker code) and the gate rates both `critical`. The report classes are `code_injection` (CWE-94) and `insecure_deserialization` (CWE-502), the name semgrep's detected-only rules already use (ADR 0010). Neither class has a PoC template, so a nightly scan reads them at probable (ADR 0021), like `command_injection`. Calibration does not measure them (#358 and #363 own calibration); coverage lists them after `template_injection` with 0 of 0 tasks, as it lists `template_injection`. Recipes keep their six classes (ADR 0025): a recipe class is a public format change and waits for a recipe that needs one.
2. **Not looked for.** `internal/report/notlookedfor.go` holds one fixed list of classes with no sink kind or reader class: `memory_safety` (CWE-119), `xss` (CWE-79), `xxe` (CWE-611), `csrf` (CWE-352), `open_redirect` (CWE-601), `idor` (CWE-639), `missing_auth` (CWE-306), `broken_auth` (CWE-287), `prototype_pollution` (CWE-1321), `weak_crypto` (CWE-327), `race_condition` (CWE-362), `redos` (CWE-1333) and `business_logic` (CWE-840). It is not language-dependent and is printed always: the text summary on the line after `coverage:`, Markdown as a "Not looked for" section under the class table, SARIF as the `creep/not-looked-for` note and in the run's `coverage` property, JSON as `coverage.not_looked_for` (`[{class, cwe}]`). The README carries the same list between markers; `TestReadmeListsNotLookedFor` keeps the two equal. Every coverage class the pipeline cannot read (`idor`, `missing_auth`, `prototype_pollution`, calibration classes) is in the list, and no readable class is (`TestNotLookedForAgreesWithCoverage`).
3. **Report contract.** `coverage.not_looked_for` is optional in `docs/schemas/report-v1.json`, so a v1 report written before #365 stays valid; creep always writes it. SARIF rules gain `properties.tags` with `security` and `external/cwe/cwe-<n>` for each class with a known CWE (`report.ClassCWE`); a class without one gets no tag rather than a guess. Both are additive (v1 additive only, ADR 0009).
4. **Leaving the list.** A class leaves it only in the change that gives it a sink kind and a reader class, with a bench case, a calibration plan (or a note that it is uncalibrated, as here) and this ADR amended.

## Consequences

- A finding on an `eval` or `pickle.loads` sink is `code_injection` or `insecure_deserialization`; a baseline entry recorded for it as `command_injection` no longer matches, since the fingerprint covers the class (ADR 0022), so it shows up as new once.
- Discovery's prompts name eight kinds; `PromptVersion` 2 makes cached and recorded discovery replies from version 1 a miss, never served.
- A clean report on a C repository still exits 0, but every format says that memory-safety bugs were not looked for.
- The list is a promise about the binary, not about a scanner: semgrep's `xss` and `weak_crypto` stay listed, since creep detects semgrep and never runs it (ADR 0010).
