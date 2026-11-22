# ADR 0020: PoC repetitions, the reproduction bundle and `creep reproduce`

- **Status:** Proposed (needs maintainer approval)
- **Date:** 2026-11-21
- **Deciders:** @Ludocius
- **Amends:** [ADR 0009](0009-scan-and-why-contract.md) (a PoC's rate in the text, Markdown and SARIF reports; JSON v1 unchanged; a new command), [ADR 0019](0019-poc-templates.md) (its PoCs now run from `creep scan`)
- **Changes:** two new stable contracts, the reproduction bundle (`verify.Bundle`, `.creep/bundles/<id>.json`) and the `creep reproduce <id>` command; the PoC prompt and schema (`internal/verify/prompts/`, `verify.Schema`); `sandbox.AppPort`
- **Fitness function:** the rows "No finding is verified without a PoC that verified" and "A reproduction bundle holds no secret" of [architecture.md §9](../architecture.md#9-fitness-functions)

## Context

#24 made one PoC run (`verify.Run`) safe; nothing ran it. #25 asks to run each PoC against HEAD several times (default 5) so a race reads as intermittent, not as stable or absent; to keep a reproduction bundle per finding (the PoC, requests and responses, image digests, commit, database seed, timings) with no secret in it; to add `creep reproduce <id>`, which runs the PoC again offline with no model; and to show the rate of an intermittent finding in the report.

Constraints:

- `verify` may import only `sandbox`, `state` and `config` (layer table), so the model call and redaction live in the CLI.
- A false `verified` is creep's worst failure; the scanned repository builds the app, so it can make any PoC fail, pass or flap.
- JSON v1 gains no field after v0.1.0 (ADR 0009, note on ADR 0017); the maintainer decided there is no v2. The #23 amendment kept the build outcome out of JSON for this reason.
- The exit code moves only as the gate reads statuses (ADR 0009 #23 amendment).

## Options

Where the rate goes:

| Option | Pros | Cons |
|---|---|---|
| A. Text, Markdown and SARIF only; JSON reads `verified` | JSON v1 unchanged, as for the build outcome; every human and code-scanning format shows it | A JSON consumer cannot tell 3/5 from 5/5 |
| B. An optional `poc` object on a JSON finding | Every format carries it | Breaks the rule that v1 gains no field after the first release |

What a PoC that never verified does:

| Option | Pros | Cons |
|---|---|---|
| a. 0 of N discards the finding | Fewer findings | The repository builds the app: a Dockerfile that does not serve, or an app that answers creep's payloads harmlessly, would discard a real finding and pass `gates.pr` |
| b. 0 of N discards the PoC; the finding keeps the reader's `probable` | No hostile app can lower a status | The report holds probable findings a PoC could not confirm |

## Decision

Option A with b: the rate is never in JSON v1, and a PoC can only raise a finding to `verified`, never lower it.

**Repetitions.** `verify.Repeat(ctx, runner, target, poc, runs)` runs a PoC 1 to `verify.MaxRuns` (20) times, each run with its own fresh nonce (ADR 0019), and returns every `Result` with a `Rate{Verified, Runs}`. A sandbox error ends the repetition and no rate is made of the runs before it. `creep scan` uses `verify.DefaultRuns` (5):

- 5 of 5: the finding is `verified` ("verified in 5/5 runs").
- 1 to 4 of 5: the finding is `verified`, with its rate and "intermittent".
- 0 of 5: the PoC is discarded; the finding stays `probable` and gets no bundle.

`report.Finding.PoC` (`json:"-"`) holds the rate; `report.New` refuses a rate on a finding that is not verified, a rate of 0 verified runs, more verified runs than runs, and more than 20 runs.

**Scan wiring.** With `sandbox.enabled` and a built app, `creep scan` takes each `probable` finding whose class has a template that proves it (`sqli`: `sql_payload`; `path_traversal`: `path_payload`; `template_injection`: `http_request`, `http_sequence`; `verify.TemplatesFor`), in report order, at most 16 per scan. It reads the app's port from the image (`sandbox.AppPort`: the lowest declared TCP port, `EXPOSE`; none is `verification unavailable (no_port)`), starts the run's database when the repository has migrations (one that does not come up is no database, so a marker PoC is `no_database`), and starts the app (`start_failed` otherwise). For each finding it asks the model for a `verify.Request` through the gateway: the PoC system prompt for the calibrated tier (`internal/verify/prompts/`, `verify.PromptVersion` 1, a token-budget test), a user turn with the class, the allowed templates and the reader's own slice (redact.File output only), and the closed schema `verify.Schema` sent strictly; `models.Complete` refuses unknown, duplicate and case-variant keys and runs `Validate`. The PoC must pass `verify.Build` and be of an allowed template (`verify.Fits`): a `path_payload` cannot verify an SQL injection. Invalid output skips that finding; a model error (budget, transport) or a sandbox error ends the stage, and every finding left is counted as not run. The stage runs under the build's context, so the scan deadline and Ctrl+C end it, and the sandbox closes on every path.

`report.Verification` gains a `PoCSummary` (ran, verified in every run, intermittent, not run), only on `app_built`, and the reasons `no_port` and `start_failed`. The text summary, Markdown and SARIF say how many PoCs ran and how they ended; each verified finding shows its rate in the text summary, Markdown's notes and a SARIF result's message and `poc_verified_runs`/`poc_runs` properties. The verification outcome still never makes a run incomplete; the exit code moves only because `verified` is a status the gate reads, and the default gate reads probable and verified alike.

**The bundle (stable contract, version 1).** For a finding a PoC verified, `.creep/bundles/<id>.json` holds: `version`, `finding`, `class`, `commit` (HEAD read from `.git`, "" when unknown), `images` (the app's local ID, `sandbox.RunnerImage`, `sandbox.DatabaseImage` when a database ran), `seed` (the migration paths in order and `verify.SeedDigest`, a SHA-256 over each path, its length and its bytes), `port`, `database`, `poc` (the `verify.Request`), `rate` and every run with its outcome, oracle and steps (role, request, response, truncated, `elapsed_ms`, `withheld`). Every request, response and the PoC itself go through the scan's `redact.File` (the same redactor, so a value the scan masked in the code is swept from responses too); before that, the values of credential headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`, `X-Csrf-Token`) and every copy of a session value of 8 bytes or more in the run are masked (`<CREDENTIAL>`), since no redaction rule finds an opaque cookie or bearer token an `http_sequence` app issues; a text it cannot redact (too large, a line too long, the redactor full) is withheld, and a PoC it cannot redact, or that no longer decodes after redaction, writes no bundle. The bundle goes through the state store's checked handle, created with `O_EXCL` like the reports; `bundles/` is removed with the stale reports when a scan opens its state, so a committed or older bundle never passes for this run's. A finding ID names a bundle only when it is a plain file name (`verify.ValidBundleID`: no dot, colon or separator).

**`creep reproduce <id>`.** It reads no model setting, opens no model link and calls nothing: it needs `sandbox.enabled` (exit 2 otherwise, since it builds and runs the app) and a usable runtime (exit 3). It reads the bundle through `.creep`'s own checks (`state.OpenExisting`, as `creep why`), strictly (`verify.ReadBundle`: unknown fields, trailing data, another version, a rate that does not match its runs, an outcome outside the closed set, a commit or image that is not a hash are refused), rebuilds the PoC through `verify.Build` and `verify.Fits`, walks the current directory, builds the app afresh in a new sandbox (run ID `reproduce-<random>`), starts it as the scan does, and runs the PoC as many times as the scan did, by `budget.max_seconds`. It prints each run's outcome, the rate and the scan's rate, and warns when HEAD is not the bundle's commit. Exit 0 when the PoC verified in at least one run, 1 when in none, 2 for usage, configuration or a missing or refused bundle, 3 when the sandbox could not build, start or run.

## Consequences

- A hostile app can make a PoC fail (its finding stays probable, as without a sandbox) or flap (an intermittent rate), never lower a status. As ADR 0019 says, an app written to recognize creep's payloads can still make itself verified; that is a flaw in the scanned code reported against it.
- The bundle is the reproduction record, not an audit log: it shows what the runner sent and got back, redacted. A secret no rule finds is not masked, as in any text the scan sends (redact's residuals apply).
- A bundle the repository commits under `.creep` before any scan is read by `creep reproduce`; it is checked strictly and its PoC rebuilt through `Build`, so it can only run a closed template against the app the same repository builds, and the next scan removes it.
- PoC requests count against `budget.max_calls` and `budget.max_tokens` like any call, after the analysis, so they never cut it; `creep estimate` does not count them, since they depend on the reader's verdicts (at most 16, each a tier's PoC prompt, schema and one reader slice).
- `--replay` replays the PoC requests like any model call; a recording made before #25 has none, so its PoCs are not run. The PoC request has its own replay fixtures per tier (`internal/cli/testdata/replay/poc`, from the reader's slices of `testdata/apps/flask`; regenerate with `go test ./internal/cli -run TestPoCReplay -update`).
- The app gets no database URL from creep; a marker PoC verifies only when the app reaches `db:5432` from its own configuration. Wiring the synthetic credentials into the app is left to the sandbox.
- Tests: `internal/verify/repeat_test.go:TestRepeatRates` (the intermittent fixture in `testdata/repeat` yields 3 of 5 with a deterministic fake app), `TestNoVerifiedFromZeroRuns`, `TestRepeatErrors`; `bundle_test.go:TestBundleIsScrubbed`, `TestReadBundle`, `TestSeedDigest`; `credential_test.go:TestBundleMasksSessions`, `TestMaskCredentials`, `FuzzMaskCredentials`; `prompts_test.go:TestPromptTokenBudget`, `TestSchemaIsClosed`, `TestTemplatesFitTheirClass`; `internal/report/poc_test.go:TestPoCRateChecked`, `TestPoCRateInFormats`, `TestPoCSummaryChecked`; `internal/cli/poc_test.go:TestPoCRateDecidesStatus`, `TestZeroRunsStayProbable`, `TestBundleHoldsNoSecret` (the real redactor), `TestPoCStageStopsOnSandboxError`, `TestPoCStageStopsOnModelError`, `TestPoCStageBounds`; `poc_replay_test.go:TestPoCReplay`, `TestPoCReplayMissStops`; `reproduce_test.go:TestReproduceNeedsNoModel`, `TestReproduceFailsClosed`, `TestScanRemovesStaleBundles`; `internal/sandbox/appport_test.go:TestAppPort`.
