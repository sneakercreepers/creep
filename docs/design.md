# Design summary

The short version of the design, as built at v0.1 (2026-11-16). [architecture.md](architecture.md) is the source of truth for layers, contracts and fitness functions; this page keeps the original design's outline and says where the system moved away from it. Decisions that change it go through an [ADR](adr/0000-template.md).

Main purpose: find real vulnerabilities in local source code, with any model, without code leaving the machine except redacted through the gateway, saying honestly what was not evaluated, and gating CI deterministically.

## Pipeline

```
creep scan .
  1 Calibration     measure the model per vulnerability class (seeded tasks, Wilson score, tier S/M/L;
                    cached per model, endpoint and task set for 30 days; --recalibrate)
  2 Static          tree-sitter (WASM in wazero, ADR 0008): routes, sinks and auth for Flask, FastAPI and
                    Express (JS/TS); unresolved bindings fail closed; other source languages are listed as
                    unsupported_language. Optional scanners: gitleaks and osv-scanner run offline (ADR 0013);
                    semgrep is detected only (ADR 0010)
  3 Planner         sees only IDs, enums and booleans → deterministic ranking, no model call, tier step caps
  4 Reader          reads redacted slices (quarantined), answers in a closed schema
  5 Sandbox  v0.2   optional Docker/Podman, internal network, PoC against HEAD (differential in v2)
  6 Fix      v3     diff → oracle → tests, suggested only
  7 Report          verified · probable · discarded · not evaluated → SARIF, JSON v1, Markdown in .creep/
                    (HTML in v1.0); an incomplete run exits 4 (ADR 0007, ADR 0009)
```

Every model call goes through the **gateway**: `redact.File` → fragment → consent → token budget → `egress.log` write-ahead → send (HTTP) or run (command, ADR 0014).

Supporting commands: `creep why <id>` reads the last JSON report; `creep estimate` measures the requests a scan would send without a transport (ADR 0011); `--stats` prints what a scan spent; `--record`/`--replay` repeat a run with no network; `creep doctor` runs the tool canary. `creep init` and continuing a run with `creep resume` are not implemented and fail closed.

## Model contracts

- **HTTP**: OpenAI-compatible + Anthropic. The key comes only from `CREEP_API_KEY`.
- **Command**: prompt on stdin, JSON on stdout. The CLI is started only by the gateway (`EgressLog.Exec`): argv split without a shell, program never from the repository, minimal environment, empty temporary working directory, timeout and output cap, and a reply that leaves files is dropped (ADR 0014). Guarded by the tool canary at `creep doctor` and at every scan start.

No provider-specific code in the core. Presets are embedded data in `internal/presets` (ADR 0015), not a `presets/` directory read at run time: `claude-code` (verified by hand), `gemini`, `codex` and `ollama` (unverified). `gemini` and `codex` keep tools that read the host (`host_reads: unbounded`), so they warn at doctor and every scan; for untrusted code use `claude-code` or the HTTP contract.

## Fixed protections (not configurable)

- Model output never runs on the host.
- Sandbox has no internet access (v0.2; there is no sandbox yet).
- Only targets built from local source; no `--url`.
- Secrets always redacted before the gateway sends code; `egress.log` always on. Exception: the `codex` and `gemini` presets can read host files the model asks for, outside redaction (`host_reads`, ADR 0015, #229); creep warns at `doctor` and scan start.
- The planner never reads code.
- The project file (`./creep.yaml`) never loosens a CI gate, grants consent, chooses the model command (`model.contract`, `model.run`, `model.env`, `model.preset`) or enables a scanner.

Each protection has a test that is proven able to fail, run by the required CI job `protections` (#17).

## Configuration layers

1. Built-in safe defaults → 2. Org policy (`CREEP_POLICY`, can lock keys) → 3. User (`~/.creep/config.yaml`) → 4. Project (`./creep.yaml`) → 5. CLI flags.
`creep config explain` shows each final value and its source, including a preset. Privacy modes (`local-only`, `full`), include/exclude, baseline and recipes are not built yet.

## CI gates

- PR: `probable:critical` (no sandbox). Classes map to severities in ADR 0009; scanner findings are `high`.
- Nightly: `verified:high` needs the sandbox and the nightly mode, both v0.2 (#21–#25, #28). Until then nothing is `verified`.
- Exit codes: 0 ok · 1 gate · 2 usage, config or consent · 3 model, canary or calibration · 4 incomplete. An incomplete run never exits 0, even when the gate also trips.

## Dependencies

Two direct dependencies, each with an ADR: `go.yaml.in/yaml/v3` (ADR 0001) and `wazero` (ADR 0008). JSON Schema is validated in tests only, not in the binary. State is JSONL files. External scanners are optional programs on `PATH`; when missing, refused or not run, the report lists them and the classes they would cover.

## Changes since the original design

The original version of this page is in the history ([0b256d8](https://github.com/sneakercreepers/creep/blob/0b256d8/docs/design.md)). Drift is "none", "moved" (to a later version) or "changed" (by an ADR).

| Original decision | Built at v0.1 | Drift | Main purpose |
|---|---|---|---|
| Calibration per model, cached 30 days | As designed; one model per run picks the tier. Routing each task to the cheapest model that solves it is not built | None for calibration; routing across models not scheduled | Kept |
| Static: tree-sitter routes, sinks, auth | Flask, FastAPI, Express in Go code; kits as data in v0.2 ([ADR 0012](adr/0012-language-kits.md), #217); parser ~0.1 MB/s (#170, #171) | Changed by ADR 0012, moved to v0.2 | Kept; other languages are reported as not evaluated |
| Optional scanners "used when installed" | gitleaks and osv-scanner run offline with fixed arguments; semgrep detected only ([ADR 0010](adr/0010-optional-scanners-detect-only.md), [ADR 0013](adr/0013-scanner-runner.md)) | Changed by ADR 0010, 0013 | Kept; a failed scanner makes the run incomplete |
| Planner sees only IDs and enums | As designed, reflection-guarded; NoSQL sinks planned and read since v0.2 (#212) | None; NoSQL moved to v0.2 | Kept |
| Sandbox and verification | Not built | Moved to v0.2 (as planned) | Partly: findings are `probable`, never `verified` |
| Command contract with tool canary | CLI runs only through the gateway ([ADR 0014](adr/0014-command-model-through-gateway.md)) | Changed by ADR 0014 (stronger) | Kept |
| Presets as community data in `presets/` | Embedded in the binary; only `claude-code` verified; `gemini`, `codex` read the host ([ADR 0015](adr/0015-model-presets.md)) | Changed by ADR 0015 | Weakened for `gemini` and `codex`: the canary cannot see reads, so host secrets could leave unredacted. Warned, not blocked (#229) |
| Product never imports `os/exec` | `scanrun` and `gateway` only, by an exact rule in `make budget` | Changed by ADR 0013, 0014 | Kept |
| Exit codes 0–3 | Added 4 for incomplete runs, with fixed rules ([ADR 0007](adr/0007-exit-code-incomplete.md), [ADR 0009](adr/0009-scan-and-why-contract.md)) | Changed by ADR 0007, 0009 | Strengthened; known gaps let a run read as covered (#207, #213, #214) |
| Reports SARIF, JSON, Markdown, HTML | SARIF, JSON v1, Markdown; HTML in v1.0 | None | Kept |
| CI: PR and nightly gates, Action, diff | PR gate in `gates.pr`; Action, `--diff`, baseline, nightly mode in v0.2 (#26–#29) | Moved to v0.2 | Kept for full scans |
| Recorded model replies for tests | Reader fixtures are synthesized from `expected.json`; no real-model recording or public bench yet (#204, #35) | Moved (bench in v0.3) | Unproven: quality with a real small model is not measured yet |
| ~3 dependencies (YAML, wazero, JSON Schema) | 2; no schema validator in the binary | Changed (smaller) | Kept |
| Privacy modes, `creep clean`, `init` | Not built; redacted mode always on | Moved to v0.2 or later | Kept |
| Security follow-ups from reviews | Review follow-ups moved to v0.2, including redaction and config fixes (#62, #63, #70, #102) | Moved by maintainer decision (2026-11-16) | Kept for v0.1; #70 narrows redaction |
