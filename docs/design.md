# Design summary

The short version of the design, as built at v0.1 (2026-11-16) and kept current with `main` (v0.2 in progress). [architecture.md](architecture.md) is the source of truth for layers, contracts and fitness functions; this page keeps the original design's outline and says where the system moved away from it. Decisions that change it go through an [ADR](adr/0000-template.md).

Main purpose: find real vulnerabilities in local source code, with any model, without code leaving the machine except redacted through the gateway, saying honestly what was not evaluated, and gating CI deterministically.

## Pipeline

```
creep scan .
  1 Calibration     measure the model per vulnerability class (seeded tasks, Wilson score, tier S/M/L;
                    cached per model, endpoint and task set for 30 days; --recalibrate)
  2 Discovery       language-agnostic (ADR 0017, #265): an inventory by file name and bytes, a lexical
                    tripwire (one cross-language sink table matched on redacted bytes) and model
                    discovery (whole redacted files through the gateway, closed schema of line spans and
                    enums, one canary per batch; a missed canary makes the batch parse_failed), combined
                    by union only with worst-case planner flags. A stderr notice names the endpoint and
                    the number of whole files before the first call. Optional scanners: gitleaks and
                    osv-scanner run offline (ADR 0013); semgrep is detected only (ADR 0010).
  3 Planner         sees only IDs, enums, booleans and bounded numbers → deterministic ranking, no model call, tier step caps
  4 Reader          reads redacted slices (quarantined), answers in a closed schema
  5 Sandbox  v0.2   optional Docker/Podman through their CLI (ADR 0016): runtime detection, hardened
                    profile and cleanup built (#21); internal network, canary and synthetic database
                    built (#22); offline app build wired into scan, outcome in the report (#23);
                    PoC templates (#24, ADR 0019) run 5 times against HEAD per probable finding:
                    5/5 verified, 1-4/5 verified with a rate (intermittent), 0/5 stays probable;
                    a redacted reproduction bundle per verified finding (#25, ADR 0020)
  6 Fix      v3     diff → oracle → tests, suggested only
  7 Report          verified · probable · discarded · not evaluated → SARIF, JSON v1, Markdown in .creep/
                    (HTML in v1.0); an incomplete run exits 4 (ADR 0007, ADR 0009)
```

Every model call goes through the **gateway**: `redact.File` → fragment → consent → token budget → `egress.log` write-ahead → send (HTTP) or run (command, ADR 0014).

Supporting commands: `creep why <id>` reads the last JSON report; `creep reproduce <id>` runs a verified finding's PoC again from its bundle, in the sandbox, with no model (ADR 0020); `creep estimate` measures the requests a scan would send without a transport (ADR 0011); `--stats` prints what a scan spent; `--record`/`--replay` repeat a run with no network; `creep doctor` runs the tool canary and reports the sandbox runtime, rootless status and isolation; `creep clean` removes the containers creep left (ADR 0016). `creep init` and continuing a run with `creep resume` are not implemented and fail closed.

## Model contracts

- **HTTP**: OpenAI-compatible + Anthropic. The key comes only from `CREEP_API_KEY`.
- **Command**: prompt on stdin, JSON on stdout. The CLI is started only by the gateway (`EgressLog.Exec`): argv split without a shell, program never from the repository, minimal environment, empty temporary working directory, timeout and output cap, and a reply that leaves files is dropped (ADR 0014). Guarded by the tool canary at `creep doctor` and at every scan start.

No provider-specific code in the core. Presets are embedded data in `internal/presets` (ADR 0015), not a `presets/` directory read at run time: `claude-code` (verified by hand), `gemini`, `codex` and `ollama` (unverified). `gemini` and `codex` keep tools that read the host (`host_reads: unbounded`), so they warn at doctor and every scan; for untrusted code use `claude-code` or the HTTP contract.

## Fixed protections (not configurable)

- Model output never runs on the host.
- Sandbox has no internet access: every container runs with `--network=none` or on the run's `--internal` network, which a canary must find closed before each PoC batch (else the run aborts), with no published port, a read-only root, no capabilities, user 65534 and resource limits, and never mounts the runtime socket or host credentials (ADR 0016). App builds run with `--network=none` from local base images only, from a copy of the context without `.env` files, with nothing in the Dockerfile the builder would fetch; a refused or failed build is verification unavailable, never a failed scan (#23).
- Only targets built from local source; no `--url`.
- Secrets always redacted before the gateway sends code; `egress.log` always on. Exception: the `codex` and `gemini` presets can read host files the model asks for, outside redaction (`host_reads`, ADR 0015, #229); creep warns at `doctor` and scan start.
- The planner never reads code.
- The project file (`./creep.yaml`) never loosens a CI gate below the built-in, policy-limit or inherited gate, grants consent or raises a limit (`budget.*`, `model.timeout_seconds`, `model.max_output_bytes`, `calibration.cache_days` may only be lowered), and cannot set `model.contract`, `model.endpoint`, `model.name`, `model.tier`, `model.run`, `model.env`, `model.preset`, `egress.allow`, `sandbox.enabled`, `sandbox.runtime`, `scanners.enabled`, `report.formats` or `output.format`.

Each protection has a test that is proven able to fail, run by the required CI job `protections` (#17).

## Configuration layers

1. Built-in safe defaults → 2. Org policy (`CREEP_POLICY`, can lock keys) → 3. User (`~/.creep/config.yaml`) → 4. Project (`./creep.yaml`) → 5. CLI flags.
`creep config explain` shows each final value and its source, including a preset. Privacy modes (`local-only`, `full`), include/exclude, baseline and recipes are not built yet.

## CI gates

- The scan's mode picks the gate ([ADR 0021](adr/0021-gate-per-mode.md), #28): `--mode pr|nightly`; without the flag a GitHub Actions `schedule` event is nightly and anything else pr. The mode is never a config key, so the scanned repository cannot pick it. `creep config explain` and the scan's `gate:` line on stderr show the mode, how it was chosen and the gate's key and layer.
- PR: `gates.pr`, `probable:critical`. A pr scan has no sandbox: it never builds the app or runs a PoC, even with `sandbox.enabled`, so it never waits for verified findings. Classes map to severities in ADR 0009; scanner findings are `high`.
- Nightly: `gates.nightly`, `verified:high`, and `gates.pr` as well, so a nightly scan never passes what a pr scan fails. A nightly scan builds the app and runs PoCs (#23–#25). When the sandbox is off or unavailable, or a PoC candidate got no completed run, the nightly gate is read as `probable:<severity>`, so a finding nothing verified fails the run instead of passing it. A PoC that ran and never verified leaves its finding probable: `gates.pr` still fails it when it is critical; a probable high finding nothing verified (0/5, no template, a scanner finding) passes both default gates, as before #28 (ADR 0021 residual, a maintainer decision).
- The policy's `limits.gates.pr` and `limits.gates.nightly` floor both keys in every mode, and the project file may only make either gate stricter.
- Exit codes: 0 ok · 1 gate · 2 usage, config or consent · 3 model, canary, calibration or sandbox · 4 incomplete. An incomplete run never exits 0, even when the gate also trips.

## Dependencies

One direct dependency, with an ADR: `go.yaml.in/yaml/v3` (ADR 0001). `wazero` (ADR 0008) and, with it, `golang.org/x/sys` were removed at #265 (ADR 0017). JSON Schema is validated in tests only, not in the binary. State is JSONL files. External scanners are optional programs on `PATH`; when missing, refused or not run, the report lists them and the classes they would cover.

## Changes since the original design

The original version of this page is in the history ([0b256d8](https://github.com/sneakercreepers/creep/blob/0b256d8/docs/design.md)). Drift is "none", "moved" (to a later version) or "changed" (by an ADR).

| Original decision | Built at v0.1 | Drift | Main purpose |
|---|---|---|---|
| Calibration per model, cached 30 days | As designed; one model per run picks the tier. Routing each task to the cheapest model that solves it is not built | None for calibration; routing across models not scheduled | Kept |
| Static: tree-sitter routes, sinks, auth | v0.1: Flask, FastAPI, Express in Go code. v0.2: replaced by language-agnostic inventory, tripwire and model discovery ([ADR 0017](adr/0017-language-agnostic-analysis.md), #265); kits as data ([ADR 0012](adr/0012-language-kits.md), #217) and tree-sitter in wazero ([ADR 0008](adr/0008-wazero-tree-sitter.md)) are superseded | Changed by ADR 0017 (supersedes ADR 0008 and 0012) | Widened: every language is read, at the cost of whole redacted files sent to the model (ADR 0017 D1) and quality not yet measured outside the Python and JS test apps (#35) |
| Optional scanners "used when installed" | gitleaks and osv-scanner run offline with fixed arguments; semgrep detected only ([ADR 0010](adr/0010-optional-scanners-detect-only.md), [ADR 0013](adr/0013-scanner-runner.md)) | Changed by ADR 0010, 0013 | Kept; a failed scanner makes the run incomplete |
| Planner sees only IDs, enums, booleans and bounded numbers | As designed, reflection-guarded; NoSQL sinks planned and read since v0.2 (#212) | None; NoSQL moved to v0.2 | Kept |
| Sandbox and verification | Runtime detection, hardened profile, cleanup and `creep clean` (#21, [ADR 0016](adr/0016-sandbox-runtime.md)); run network, canary and synthetic database (#22, ADR 0016 amendment); offline app build from the repository's own compose file or Dockerfile, run by `creep scan` with the outcome (built, or `verification unavailable` and its reason) in the text, Markdown and SARIF reports, never in the exit code (#23, ADR 0016 amendment, ADR 0009 amendment); PoC verification not built | Changed by ADR 0016 (CLI, not the API socket; creep never pulls the pinned images); verification moved to v0.2 (#24, #25) | Partly: findings are `probable`, never `verified` |
| Command contract with tool canary | CLI runs only through the gateway ([ADR 0014](adr/0014-command-model-through-gateway.md)) | Changed by ADR 0014 (stronger) | Kept |
| Presets as community data in `presets/` | Embedded in the binary; only `claude-code` verified; `gemini`, `codex` read the host ([ADR 0015](adr/0015-model-presets.md)) | Changed by ADR 0015 | Weakened for `gemini` and `codex`: the canary cannot see reads, so host secrets could leave unredacted. Warned, not blocked (#229) |
| Product never imports `os/exec` | `scanrun`, `sandbox` and `gateway` only, by an exact rule in `make budget` | Changed by ADR 0013, 0014, 0016 | Kept |
| Exit codes 0–3 | Added 4 for incomplete runs, with fixed rules ([ADR 0007](adr/0007-exit-code-incomplete.md), [ADR 0009](adr/0009-scan-and-why-contract.md)) | Changed by ADR 0007, 0009 | Strengthened; a directory link the walk does not cover is listed `not_regular` and makes the run incomplete (#214) |
| Reports SARIF, JSON, Markdown, HTML | SARIF, JSON v1, Markdown; HTML in v1.0 | None | Kept |
| CI: PR and nightly gates, Action, diff | PR gate in `gates.pr`; v0.2: `--mode pr\|nightly` with `gates.nightly` (plus `gates.pr`) and a fail-closed nightly gate without verification ([ADR 0021](adr/0021-gate-per-mode.md), #28); Action, `--diff`, baseline in v0.2 (#26, #27, #29) | Moved to v0.2 | Kept for full scans |
| Recorded model replies for tests | Reader fixtures are synthesized from `expected.json`; no real-model recording or public bench yet (#204, #35) | Moved (bench in v0.3) | Unproven: quality with a real small model is not measured yet |
| ~3 dependencies (YAML, wazero, JSON Schema) | 1 (YAML) since #265; no schema validator in the binary | Changed (smaller) | Kept |
| Privacy modes, `creep clean`, `init` | `creep clean` removes creep's containers (#21); privacy modes and `init` not built; redacted mode always on | Moved to v0.2 or later | Kept |
| Security follow-ups from reviews | Review follow-ups moved to v0.2, including redaction and config fixes (#62, #63, #70, #102) | Moved by maintainer decision (2026-11-16) | Kept for v0.1; #70 narrows redaction |
