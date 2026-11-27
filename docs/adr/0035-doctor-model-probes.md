# ADR 0035: `creep doctor` probes the model with synthetic calls

- **Status:** Accepted (maintainer, 2026-11-27)
- **Date:** 2026-11-27
- **Deciders:** @Ludocius
- **Changes:** `creep doctor` now sends model calls for every contract (it sent none for HTTP contracts, and only the tool canary for command models): one discovery call on a batch holding only the canary and one context probe. No new flag, config key, dependency or exit code; the new outcomes map to existing codes. Amends [ADR 0014](0014-command-model-through-gateway.md) (doctor ran only the tool canary).
- **Threat model:** [threat-model.md](../threat-model.md) R19, C4

## Context

#362, #367: on `qwen2.5-coder:1.5b` under Ollama, `creep doctor` exited 0 while every discovery batch was about to fail (canary missed, schema broken), and a default Ollama install truncates long inputs silently (its `num_ctx` default is far below what discovery sends) and drops the system prompt with them. doctor never contacted an HTTP model, so it could not say so before a 20-minute calibration and a scan that exits 4.

## Options

1. **Keep doctor offline for HTTP models; document `num_ctx`.** Cheapest, but the user learns only from a failed scan.
2. **Run calibration from doctor.** Measures everything, but costs about 110 calls (20 minutes on a CPU) and writes the calibration cache from a command meant to be quick.
3. **Two synthetic probes through the gateway** (chosen): a discovery call whose batch is only creep's canary, and one context probe as large as the tier's largest discovery call.

## Decision

- doctor opens a fresh run directory and connects through the same gateway path as a scan: consent (prompt outside CI, the policy's list in CI), the token and call budget, write-ahead `egress.log`, the `egress.allow` client. For a command model the tool canary still runs first and still exits 3 when the CLI has tools.
- **Tier.** doctor reads the calibration cache only (`CacheOnly`, as `creep resume` does) and uses the cached tier; with none it uses S and says so. doctor never calibrates and writes no cache.
- **Discovery probe** (`discover.Probe`, purpose `doctor.discover`): the tier's system prompt and the scan's schema and grammar, with a user turn that is the canary file alone, with the scan's reply cap and the same canary rule (window of 2 lines, R19). No repository file is read or sent.
- **Context probe** (`calibrate.ContextFits`, purpose `doctor-context`): calibration's synthetic filler of at least `discover.CallTokens(tier)` bytes, the needle on its first line, so an endpoint that cuts the start of a long input loses it as a scan would lose its system prompt. It is capped at 144 KiB and has its own token-budget test.
- **Outcomes.** A call that fails (transport, status, consent, budget) prints the error and exits as a scan would (3, or 2 for consent and configuration). A reply that breaks the schema, cites lines outside the batch or misses the canary, and a context that does not hold the tier's discovery call, print a `warning:` line and keep exit 0: they predict a scan that exits 4, which reports the same thing, and a probabilistic model should not fail a CI step that only checks the setup. The context warning names the Ollama `num_ctx` fix.

## Consequences

- doctor now costs two to four calls (a retry each) and up to about 150 KiB of input at tier L; the README nightly example that runs doctor spends them every night.
- doctor needs consent for an HTTP endpoint, as a scan does; in CI the policy grants it.
- `egress.log` of a doctor run lists the probes under their own purposes.
- Tests: `cli/doctormodel_test.go:TestDoctorProbesTheModel` (reachable, cached tier, canary missed, short context, unreachable, no repository text in any call), `discover/probe_test.go:TestProbe`, `calibrate/contextfits_test.go:TestContextFits`.
