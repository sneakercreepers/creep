# ADR 0038: Live replay fixtures from the pinned local model

- **Status:** Proposed
- **Date:** 2026-11-28
- **Deciders:** @Ludocius
- **Amends:** [ADR 0030](0030-creep-bench.md) (the published fixture is a live recording)
- **Changes:** the layer table (§3 of [architecture.md](../architecture.md)): `internal/gateway/gatewaytest` moves from layer 2 to layer 3 and may import `gateway`; the rows of `calibrate`, `reader` and `discover` add `gateway/gatewaytest`, which `make budget` still allows only in `_test.go` files. A new workflow, `.github/workflows/live-record.yml`. No product code path, exit code, flag, dependency or network path changes.

## Context

#356: every quality number creep publishes rested on synthesized replies. The reader fixtures for S, M and L, the small-model discovery fixture (#370), the calibration fixtures (#377) and the published bench fixture were all written by an oracle from the ground truth, so they pin creep's pipeline, not a model's judgement. The maintainer decided that the live recordings come from the pinned Ollama model the nightly bench already runs on the GitHub-hosted runner (`qwen2.5-coder:1.5b`, manifest digest `d7372fd8…`): no cloud model, no key, no secret.

That model is unfit by ADR 0036 (`below_chance`) and calibrates at tier S. It can honestly provide only what it produces: a calibration, the tier-S reader replies, a tier-S discovery batch and a bench run (where the bench forces each tier, so the M and L numbers are this model's answers to the M and L prompts, not those of a model that calibrates there). Live reader fixtures at M and L need a model that calibrates at M or L.

Recording a fixture from a live model inside a package test needs the real gateway (invariant 2), and the code that does so is shared by three packages. `gatewaytest` is the test-only package next to the gateway, but at layer 2 it may not import `gateway`, and the three packages' rows do not list it.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. A copy of the live sender, reply normalization and hygiene check in each package's tests | No layer change | Three copies of the code that decides what a committed fixture may hold; one drifting is a leak |
| B. `gatewaytest` at layer 3, importing `gateway`, listed by the three packages | One implementation, already test-only by `make budget` | Loosens three rows and moves one, so it needs this ADR |
| C. `creep scan --record` produces the fixtures | Product path | It records under the user's secret, keyed on endpoint and a run label, into the run-state store; the fixtures key on the body alone (internal/reader doc.go). Changing that is a run-state contract change for a test need |

## Decision

Option B.

- `gatewaytest.Live` sends a recording run's calls through `gateway.EgressLog.Send` with consent for one origin, a bounded budget and `egress.log` in a temporary run directory. `LiveFromEnv` reads the model from `CREEP_LIVE_ENDPOINT` and `CREEP_LIVE_MODEL` and refuses any endpoint but `http://127.0.0.1:<port>`.
- `Normalize` keeps of each reply the model name, every choice's message (content byte for byte) and finish reason, and the token counts, with the response ID `chatcmpl-replay`; `created`, `system_fingerprint` and every other provider field are dropped. The imported bench fixture's endpoint becomes `https://models.replay.invalid/v1` (its request bodies do not depend on it).
- Each live fixture has a `provenance.json` header (`gatewaytest.Provenance`): synthesized or not, the model and its base model and digest, tier, recording date, workflow run, and the outcomes the replies replay to. A live fixture's replay is checked against those outcomes, never against the ground truth: the model is wrong where it is wrong. The synthesized fixtures that stay (reader M and L, calibration seed 1) carry a header that says so.
- `-update` never overwrites a live fixture with synthesized replies; only a run with the live variables set re-records it, and the bench fixture is replaced only from a named recording (`CREEP_LIVE_BENCH_FIXTURE`).
- `live-record.yml` (dispatch, and pull requests that change it) records all of them on the runner, replays them offline and uploads the normalized fixtures as an artifact. Nothing is pushed: a maintainer reviews the artifact (no secrets, no text beyond the test apps and corpus, every reply parses) and commits it.
- Tests fail on a committed reply that holds a URL outside `.invalid`, a key shape, a provider response ID or a routing field (threat model B8).

## Consequences

- Reader S, the small-model discovery batch, one calibration and the published bench numbers are live recordings of the pinned 1.5B model; reader M and L and the seed-1 calibration set stay synthesized, and their headers, the README and ADR 0030 say so.
- A change to a prompt, the schema or the corpus misses the live recordings, as it does the synthesized ones; the fix is a dispatch of `live-record.yml`, not `-update`.
- Re-pinning the bench model re-pins the recordings: both workflows name the same digest.
- The published bench numbers are now a weak model's: low recall and high false-positive rates. That is the honest measurement; ADR 0036 already refuses this model in a scan without `--allow-unfit-model`.
