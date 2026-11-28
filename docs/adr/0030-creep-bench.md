# ADR 0030: creep-bench, its results JSON and published replay fixtures

- **Status:** Accepted (maintainer, 2026-11-23)
- **Date:** 2026-11-23
- **Deciders:** @Ludocius
- **Changes:** one command, `creep bench` (no new flag: it reads the global `--replay`, `--record`, `--format` and `--config`); one new public JSON document, the bench results (`schema_version` 1, published in `docs/bench/results.json`); one new package, `internal/bench` (layer 0, no internal import). No new dependency, network path, config key or exit code.
- **User guide:** wiki [Sharing model results](https://github.com/sneakercreepers/creep/wiki/Sharing-model-results) (#38), linked from CONTRIBUTING.md and the Show and tell form
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

**Amendment (#356, [ADR 0038](0038-live-replay-fixtures.md)):** the published fixture is now a live recording (`"synthesized": false`) of the nightly bench's digest-pinned `creep-bench-qwen2.5-coder-1.5b-d7372fd82851` (`qwen2.5-coder:1.5b`), recorded 2026-11-28 by `live-record.yml` ([run](https://github.com/sneakercreepers/creep/actions/runs/46103486289)) on the corpus with SHA-256 `5b862f55…`; its endpoint is a `.invalid` placeholder and each reply keeps only the model's message, finish reason and token counts. It is replaced only by importing a new recording (`CREEP_LIVE_BENCH_FIXTURE=… go test ./internal/cli -run TestBenchPublished -update`); `-update` alone rewrites `docs/bench` from the committed fixture and never puts the oracle's replies back. The numbers are one unfit model's (ADR 0036): recall 10/12 at every forced tier, false positives 11/12 at S and 10/12 at M and L.

**Smoke runs.** OWASP Juice Shop and PyGoat are listed in the results as `skipped`, with the reason: creep downloads nothing (invariant 5) and they have no ground truth to score. An operator who wants a smoke run scans their own local clone with `creep scan`.

## Consequences

- Easier: every change to discovery, the planner, slicing or coverage shows in the published numbers through `TestBenchPublished`; a coverage claim that does not hold shows as a silent miss.
- Harder: a prompt, schema or pipeline change needs the fixture regenerated (`-update`), like the reader's fixtures; the bench's `benchPlanAndRead` mirrors scan's `planAndRead` without a session and must follow it.
- Until #36 publishes a live run, the published numbers say nothing about a model; the Markdown says so above the tables.
- Follow-ups: #36 (nightly live run and regression threshold); command-contract models in the bench once a fixture can rebuild a command client.

## Amendments

- **Nightly live bench, cloud runs and the regression threshold (#36, 2026-11-24).** `.github/workflows/bench.yml` runs `creep bench --record --format json` against a live model; it adds no command, flag, config key or exit code.
  - **Nightly, free.** Every night and on a manual dispatch, the `local` job serves `qwen2.5-coder:1.5b` from an Ollama service container (image pinned by digest) on the GitHub-hosted runner, bound to `127.0.0.1:11434`. The model is pinned by its manifest digest, which `.github/scripts/bench-ollama.sh` checks after the pull, and creep reads it as `creep-bench-qwen2.5-coder-1.5b`, a copy with temperature 0, a fixed seed and a 16384-token context, so the numbers move only when creep or the pin does. The policy (`.github/scripts/bench-policy.sh`) consents only to that origin; plain http is accepted only for `127.0.0.1`. When `creep bench` finishes (exit 0, or 4 when some case runs were incomplete, a reply that fails the schema included), the results JSON and the recorded fixture are uploaded as the `bench-local` artifact for 14 days. When it does not (exit 2 for usage or config, 3 for a model, transport or replay failure, or an earlier step failing), nothing is uploaded as `bench-local`; the run directory goes to `bench-local-debug` for 7 days instead. That artifact holds `egress.log`, the fixture and the redacted text of the public corpus the bench sent, and never the key (B5), so it is as public as the corpus itself. A pull request that changes the workflow, its scripts or the gate runs this job too, with a read-only token and no secret.
  - **Cloud, manual.** The `cloud` job runs only on `workflow_dispatch` with `model: cloud`, only in `sneakercreepers/creep` and only from `main`, in the `bench-cloud` environment (maintainer approval, deployments only from the `main` branch by a custom branch policy, since `main` is protected by a ruleset rather than classic branch protection; `.github/settings/bench-cloud-environment.json`, `make repo-settings`, drift in `make repo-settings-check`). The environment's variables `BENCH_CONTRACT` and `BENCH_MODEL` and its secret `BENCH_ENDPOINT` (a secret since the release review, so GitHub masks it in every log line) are checked against closed patterns before they are written into the policy, and its secret `CREEP_API_KEY` reaches only the `creep bench` step. No `pull_request_target` trigger exists, so a fork never runs this job or sees the key. Only its `results.json` is uploaded, as `bench-cloud` (14 days), when the bench finishes; the fixture and the run directory never are (release-review amendment below); the results are not gated: there is no cloud baseline.
  - **Regression threshold: 0.10 per tier.** `internal/tools/benchgate` sums each tier's counts over its classes and fails when, against the committed baseline `internal/tools/benchgate/baseline.json`, recall or honesty falls, or the false-positive rate rises, by more than 0.10 (exactly 0.10 passes). Per tier, not per class: a class has one or two cases, so one reply moves it by 0.5, while a tier of about twelve vulnerable twins moves by about 0.08 per reply, so one changed reply passes and two fail. A rate the baseline measured and the new run did not, or a tier missing from the run, fails. A baseline from another corpus digest or model fails until it is set again, and synthesized results are refused on either side. The nightly job runs the gate after uploading, and the release workflow's `bench-gate` job, which the `release` job needs, runs it on the newest `bench-local` artifact of a scheduled or dispatched run on `main` of this repository (`.github/scripts/bench-latest.sh`); no such artifact within 14 days blocks the release too. Because only a finished bench uploads `bench-local`, a night that failed for infrastructure (model pull, Ollama, runner) does not hide an earlier good run, while a night whose gate failed keeps its results, so a regression blocks the release until a newer run measures better. Recovery: dispatch the Bench workflow with `model: local` on `main`, then re-run the release.
  - **Setting the baseline.** A small model's first numbers are not known before the first nightly run, so the committed baseline starts without tiers, and the gate passes with "no baseline set yet": it fails only on a measured regression, never on a missing measurement. A maintainer sets it by downloading a nightly `bench-local` artifact, reviewing `results.json`, and committing it as `baseline.json` in a pull request through the full loop (it is code, not documentation). `TestCommittedBaseline` fails a set baseline whose corpus digest is not the embedded corpus, so a corpus change resets the baseline (no tiers) or re-measures it in the same pull request. Raising the baseline is a judgement call; lowering it is accepting a regression and says why in the PR. The published numbers in `docs/bench/` stay synthesized until a maintainer publishes a reviewed live fixture.
- **Cloud bench publishes no endpoint or reply; the first baseline; one rate owner (v0.3 release review, 2026-11-24).** This repository is public, so its workflow logs and artifacts are too. `BENCH_ENDPOINT` is an environment secret, not a variable, and reaches only the policy step: the runner prints a job's and a step's variable env in the step header before any mask applies, while a secret is masked everywhere (the maintainer moves the value from the variable to a `bench-cloud` secret of the same name). `bench-policy.sh` also masks a cloud endpoint and its host (`::add-mask::`) before it prints anything and names only the contract and model, so neither the policy step nor a later creep error shows the origin; the local origin (`127.0.0.1`) is still printed. The `cloud` job uploads only `results.json` (counts and the model name, which is the published label of the result) as `bench-cloud`: the recorded fixture (the endpoint and the provider's raw replies, with response IDs and routing fields) and the run directory (`egress.log`) are never uploaded, not even on failure, and `bench-cloud-debug` is gone; a maintainer who needs a cloud fixture records it locally (`creep bench --record`). The fixture still stores the endpoint in the 0600 run directory, where the local job's loopback endpoint is harmless. The gate does not compare a tier whose case runs are more than half incomplete in the baseline (`incomplete_runs > runs/2`): its counts rest on the few runs that finished, so two nightlies of the same tree differ past the threshold. It prints that tier as not compared. A tier more than half incomplete in the results against a baseline tier that was not fails closed as a regression, since a model that stops answering in the schema must not pass with a note; if the cause was the runner or the model pull, the recovery is to re-dispatch the Bench workflow with `model: local` on `main`. The baseline stays empty: the only nightly so far (run 45403852367, 69 of 72 case runs incomplete, every tier mostly incomplete) would compare nothing. The maintainer sets the first baseline, as above, from a nightly whose tiers are mostly complete; until then the release gate blocks only on a missing nightly, which is a stated residual (release review I1). The gate's recall, false-positive rate and honesty now come from `bench.TierResult.Totals` (rounded to three decimals, as published), so `bench` alone defines them.
