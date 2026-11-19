# ADR 0011: `creep estimate`, `--stats` and prices

- **Status:** Accepted (maintainer approval on PR #219, 2026-11-16)
- **Date:** 2026-11-16
- **Deciders:** @Ludocius
- **Changes:** the CLI contract: a new command `estimate` and the global flags `--stats`, `--price-in` and `--price-out`

## Context

#15 asks for the cost and time of a scan before it runs (tokens and calls for subscriptions, money for APIs) and for what a run spent afterwards (time per phase, cache hit rate, tokens, cost). ADR 0009 fixed the `scan` and `why` contract and does not cover either. Constraints:

- `estimate` must make no network call and no model call (invariants 1, 2 and 5). Only `internal/gateway` may open a connection.
- Output must never carry repository text unescaped.
- Acceptance: within ±30% of what a scan spends on the testdata apps.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Upper bounds only: `reader.CallTokens(tier)` per planned hypothesis | Trivial | Several times the real spend (the slice budget is a cap, not a size); fails ±30% |
| B. Build the scan's own requests (static graph → planner → slicer → `reader.Evaluate`) and hand them to a send function with no transport that measures and refuses them | Exact request bodies, exact cache keys (calls already in `.creep/cache` are known), exact gateway reservations; reuses the scan's code paths | Runs redaction and slicing locally (seconds on large repos); token count still needs a bytes-per-token ratio |
| C. A token counter per provider tokenizer | Exact tokens | A dependency per tokenizer (ADR each), and none exists for local models |
| D. A built-in price table | Cost without flags | Prices change often; a stale table is wrong without saying so |

## Decision

Option B, prices from flags only (not D), and this contract. What decided it: the scan's own request bodies are the most accurate input there is without a tokenizer, and measuring them needs no new code path that could reach the network.

**`creep estimate [.]`** estimates a scan of the current directory. It reads the config like `scan`, but needs no API key and accepts any `model.contract`; it never creates `.creep`. It walks the repository with the static extractor, then for each tier S, M and L plans with the scan's budget and builds every slice. Each request goes through `models.HTTP` with the scan's options and a send function that has no client, dialer or gateway link: it records the body length, the gateway reservation and whether `.creep/cache` holds the reply, and returns an error. The calibration cache is checked through the same path with a model that cannot send; on a miss, calibration is measured once against a canned unparseable reply and reported as a lower bound (larger context probes follow only if the model passes the first), and its calls are added to every tier. It prints text only (`--format` other than text exits 2); the numbers are counts, tier names and reason IDs, never paths. Tokens are request bytes / 4.5 plus 40 output tokens per uncached call; time is uncached calls × 5 s, since the scan makes one call at a time. It warns when the gateway's reservations would pass `budget.max_tokens` or the uncached calls `budget.max_calls`, lists sinks the plan leaves out by reason, and predicts the incomplete reason the scan would end with. It exits 0, or 2 for usage and configuration errors. Since #260, `budget.max_seconds` bounds the estimate as it bounds a scan (ADR 0009 amendment): past it the estimate reads nothing more, counts what it did not reach as `budget`, prints `PARTIAL ESTIMATE` and exits 4, so a crafted repository cannot hold it for minutes nor make a cut estimate read as whole.

**`--stats`** (scan) prints, after the result, the time of each phase (`calibrate`, `static`, `plan`, `read`, `report`), model requests (sent, served from the run-state cache, failed, hit rate), requests by purpose, tokens in and out as the provider reported them for sent calls, tokens the cached replies report, and the cost. It goes to stdout with `--format text` and to stderr otherwise, so a JSON, SARIF or Markdown report on stdout stays valid. The counters wrap the send function on both sides of the cache, so they hold only numbers and the pipeline's own purpose labels.

**`--price-in`, `--price-out`** are prices per 1M tokens, 0 to 10^6, in whatever currency the user reads them in; NaN, Inf and negative values exit 2. With neither set, no cost is printed. With `model.contract: command` no cost is printed: a subscription CLI spends quota, so calls and tokens are the measure.

Like every flag, the three are global (`flag`, no framework); commands that do not use them ignore them.

## Consequences

- `estimate` reuses `planSinks`, `targetsFor`, `incompleteReason` and the new `modelOptions`, so a change to the scan's model options or plan changes the estimate with it. `TestEstimateSourceHasNoTransport` fails if an estimate source names a transport; `TestEstimateMakesNoModelCalls` fails if estimate asks for one or hands calibration a model that can send.
- `TestEstimateWithin30Percent` compares the estimate with a recorded scan on each testdata app, with a fake model that reports usage as a tokenizer pre-tokenizer would. Real tokenizers count at least that many tokens, so the ratio (4.5 bytes per token) may need a change once real runs are measured; it is one constant.
- Stats are kept in memory, not in the run state: the JSONL run state (#8) records step IDs for resume, and timings are not needed to resume.
- The calibration lower bound leaves out the larger context probes (up to about 160 KiB of input) for models that pass the first.
