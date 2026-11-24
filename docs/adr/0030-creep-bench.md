# ADR 0030: creep-bench, its results JSON and published replay fixtures

- **Status:** Accepted (maintainer, 2026-11-23)
- **Date:** 2026-11-23
- **Deciders:** @Ludocius
- **Changes:** one command, `creep bench` (no new flag: it reads the global `--replay`, `--record`, `--format` and `--config`); one new public JSON document, the bench results (`schema_version` 1, published in `docs/bench/results.json`); one new package, `internal/bench` (layer 0, no internal import). No new dependency, network path, config key or exit code.
- **Fitness function:** [architecture.md §9](../architecture.md#9-fitness-functions), row "The bench corpus is disjoint from calibration" (`internal/bench/corpus_test.go:TestCorpusDisjointFromCalibration`), and row "Published bench numbers replay" (`internal/cli/bench_test.go:TestBenchPublished`)

## Context

#35 asks creep to measure itself the way it asks users to trust it: detection, false positives, and whether the coverage it claims is real, per class and per tier S, M and L, published as JSON and Markdown and reproducible with `--replay`. Constraints:

- Calibration (`internal/calibrate`) already scores the user's model on generated tasks; a bench built from the same templates would measure what calibration tuned on.
- Invariant 5: creep downloads nothing, so the issue's smoke runs against OWASP Juice Shop and PyGoat cannot fetch them.
- No API key is available to the project, and the reader's fixtures are already synthesized from ground truth (#204), so the first published numbers cannot come from a live model either.
- #36 will run the bench nightly against a local model, so the command must also run live, through the gateway, and record what it got.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. A reader-only bench: give the reader each case's true hypothesis | Few calls; isolates the model's judgement | Measures neither discovery, the tripwire nor the planner, and no coverage claim exists to check, so honesty cannot be measured |
| B. Every case through the scan pipeline (discovery, planner, reader, coverage) at a forced tier, with an embedded corpus and an embedded fixture | Measures what a scan does, including the coverage it claims; one code path for live, record and replay; replay needs no file, config or state | More calls per case (one discovery batch plus the reader); the bench must keep in step with scan's pipeline |
| C. Run `creep scan` as a subprocess on a checked-out corpus | Exactly the scan binary | Calibration would pick one tier; needs files on disk and a model per run; replay would go through the user's signed run state, which a published fixture cannot use |

## Decision

Option B, because only the full pipeline makes a coverage claim, and honesty is about that claim.

**Corpus.** `internal/bench/corpus/<id>/` holds `case.json` (version 1, decoded strictly: id, class, language, the file name the scan sees, and for each twin the text of its entry and sink lines, each on exactly one line) and `vulnerable.src` and `safe.src`. Cases are embedded in the binary. Classes are calibration's and template injection; a case of a class the pipeline cannot read (idor) shows that the run says `not evaluated` instead of claiming it. The corpus is disjoint from the calibration templates: no corpus line of 16 or more characters, whitespace collapsed, matches a template line with its slots read as any identifier (`TestCorpusDisjointFromCalibration`, run by `make check` in CI). A safe twin has no defensible finding in any class, as calibration's twins (#162).

**Run.** For each tier S, M, L, each case and each twin, `creep bench` runs discovery, the planner and the reader on a one-file repository at that tier, with a fresh redactor, the default token budget and a fixed public canary seed (only the bench uses it; a scan's seed stays from `crypto/rand`). No calibration, sandbox, scanner, recipe or baseline takes part. Calls go through one `models.HTTP` in a fixed order.

**Scores**, per tier and class: recall (vulnerable twins with a probable or verified finding of the class within 2 lines of the sink), false-positive rate (safe twins with any probable or verified finding, of any class), and honesty: of the vulnerable twins whose run reported the class `covered`, the share that found the planted vulnerability. A miss the run reported as partial or not evaluated is an honest miss; one it reported covered is a silent miss, counted apart. A rate over nothing is `null`. Coverage classes with no corpus case are listed as `unmeasured_classes` and named on the page, so their absence is never read as a score.

**Modes.**

- `creep bench --replay` builds the client from the embedded fixture's settings (contract, model name, structured mode, output tokens, retries) and answers each request from the fixture by the SHA-256 of its body. It reads no config, opens no state and starts no network; a request the fixture has no reply for fails the bench with exit 3.
- `creep bench` uses the configured model through the gateway (consent, budget, `egress.log`) in a run directory of `./.creep`, like a scan. Only the `openai` and `anthropic` contracts: a fixture must rebuild the HTTP client that made its bodies. A model CLI exits 2.
- `creep bench --record` also writes the run's fixture, `bench-fixture.json`, into its run directory, for a maintainer to review and publish as `internal/bench/fixtures/published.json`. A body asked twice is answered with its first reply, so a live run and its replay agree.

Exit codes: 0, or 4 when any case run would have exited 4 (its numbers are not all measured); 2 for usage and config; 3 for a model failure or a replay miss.

**Output contract.** `--format json` prints the results JSON; `text` and `markdown` print the Markdown page; `sarif` exits 2. JSON `schema_version` 1:

```json
{
  "schema_version": 1,
  "corpus": {"cases": 12, "sha256": "<hex>"},
  "model": {"contract": "openai", "name": "replay-model", "synthesized": true},
  "tiers": [{"tier": "S", "runs": 24, "incomplete_runs": 0, "classes": [
    {"class": "sqli", "vulnerable": 2, "detected": 2, "recall": 1,
     "safe": 2, "false_positives": 0, "false_positive_rate": 0,
     "claimed_covered": 2, "silent_misses": 0, "honesty": 1}]}],
  "unmeasured_classes": ["missing_auth", "prototype_pollution"],
  "smoke": [{"target": "OWASP Juice Shop", "status": "skipped", "reason": "..."}]
}
```

Rates are rounded to three decimals. Adding a field is compatible; renaming or removing one, or changing its meaning, bumps `schema_version`.

**Published numbers.** `docs/bench/results.json` and `docs/bench/results.md` are what `creep bench --replay` prints; `TestBenchPublished` fails when they differ. The published fixture is synthesized (`"synthesized": true`): an oracle in `internal/cli/benchoracle_test.go` that recognizes each twin by its code answered every call as an always-right model would, so the numbers measure creep's pipeline (inventory, tripwire, planner, slicing, coverage), not a model's judgement. `go test ./internal/cli -run TestBenchPublished -update` regenerates both. A live run (#36) replaces them.

**Smoke runs.** OWASP Juice Shop and PyGoat are listed in the results as `skipped`, with the reason: creep downloads nothing (invariant 5) and they have no ground truth to score. An operator who wants a smoke run scans their own local clone with `creep scan`.

## Consequences

- Easier: every change to discovery, the planner, slicing or coverage shows in the published numbers through `TestBenchPublished`; a coverage claim that does not hold shows as a silent miss.
- Harder: a prompt, schema or pipeline change needs the fixture regenerated (`-update`), like the reader's fixtures; the bench's `benchPlanAndRead` mirrors scan's `planAndRead` without a session and must follow it.
- Until #36 publishes a live run, the published numbers say nothing about a model; the Markdown says so above the tables.
- Follow-ups: #36 (nightly live run and regression threshold); command-contract models in the bench once a fixture can rebuild a command client.
