# Architecture

This is the source of truth for what each part of `creep` does, which way dependencies may point, and which contracts are stable. Decisions that change it go through an ADR ([index](#adr-index)). The package-by-package list is generated in [map.md](map.md) (`make map`), and the trust boundaries, attackers and mitigations are in [threat-model.md](threat-model.md).

## 1. Context

```
            ┌──────────────┐  local repo (untrusted content)
 developer ─┤              │◄──────────────────────────────
 or CI      │  creep (one  │
 (flags,    │  Go binary)  │──HTTPS──► model endpoints (allowlisted, consented)
  config,   │              │──API────► Docker/Podman (v0.2, sandbox only)
  policy)   └──────┬───────┘
                   ▼
   reports (SARIF/JSON/MD) · run state (JSONL) · egress.log · payloads/
```

- The scanned repository is **untrusted input**. Its text can only reach the reader and the redacted gateway payload. It can never reach the planner, a shell or config that loosens a gate.
- The only network peers are configured model endpoints. There is no telemetry or update check by default.
- There is no server and no database. Each run is independent; state is files.

## 2. Pipeline

| Step | Component | Input | Output | Version |
|---|---|---|---|---|
| 1 | calibrate | model contract, seeded templates | per-class scores, tier S/M/L | v0.1 |
| 2 | static | repo files | route/sink/auth graph as **IDs and enums** | v0.1 |
| 3 | planner | IDs, enums, booleans, calibration | prioritized hypotheses | v0.1 |
| 4 | reader | redacted slices + hypothesis | closed-schema verdicts | v0.1 |
| 5 | sandbox + verify | app build, PoC template | verified / discarded | v0.2 |
| 6 | fix | verified finding | suggested diff | v3 |
| 7 | report | run state | SARIF, JSON, Markdown (HTML v1.0) | v0.1 |

Every model call in steps 1, 3 and 4 goes through the gateway, in this order: `redact.File` → fragment → consent → allowlisted dialer → `egress.log` write-ahead → send.

## 3. Components and layers

A package may import only packages in **lower** layers and only those listed in its row. `make budget` enforces this table (#119), so this block is data and must stay parseable.

```layers
# layer  package                 may import (internal only)
0        internal/exitcode       -
0        internal/buildinfo      -
1        internal/config         exitcode
1        internal/redact         -
2        internal/gateway        config redact exitcode
3        internal/models         gateway config
3        internal/state          config
4        internal/static         state config
4        internal/calibrate      models gateway redact state config
4        internal/planner        models state config
4        internal/reader         models gateway redact state config
4        internal/sandbox        state config
5        internal/report         state config buildinfo
5        internal/verify         sandbox state config
5        internal/scanrun        static
6        internal/cli            *
6        internal/mcp            report state config
7        cmd/creep               cli
-        internal/tools/*        (build tooling; never imported by the product)
```

| Package | Responsibility | Invariants it owns | State |
|---|---|---|---|
| `exitcode` | Process exit codes | 0 ok · 1 gate · 2 config/consent · 3 model/sandbox · 4 incomplete (ADR 0007) | ✅ |
| `buildinfo` | Version and provenance strings | none | ✅ |
| `config` | Five config layers, org policy, CI detection | Project file never loosens CI gates or grants consent (#61, #82), and may only remove optional scanners, never enable one (#221, ADR 0013) | ✅ (#62, #63 open) |
| `redact` | Secret and PII redaction with stable markers | Whole file redacted before fragmenting; linear time; `ErrRunFull` fails closed; one call adds at most its share of the run cap (`ErrTooManyValues`: file not scanned, run goes on) | ✅ (follow-ups open) |
| `gateway` | **Only** network path | Allowlist before DNS, TLS, pinning, no redirects, consent, run and endpoint token budget, AIMD concurrency, write-ahead `egress.log`, opaque client | ✅ |
| `models` | HTTP and command contracts, tool canary | No provider SDK; model output decoded into closed structs, never executed; key only from `CREEP_API_KEY` | ✅ HTTP (#5); ⬜ command #6 |
| `state` | JSONL run state, `--record`, `--replay`, resume | Append-only; replay is deterministic | ⬜ #8 |
| `static` | tree-sitter (WASM) routes, sinks and auth; optional scanners | Output is IDs and enums only; grammars run in wazero with memory, node and time caps, and guest records are validated; `DynamicArg` fails closed (constant only if every binding is a constant simple assignment, closures included for JavaScript); Express auth is middleware read in source order (per-route, `use` before the route or mount, mount-level), never claimed for dynamic guard paths; vendor, generated (exact generator markers in the leading comments) and minified files are listed as `File.Ignored`, never dropped; paths are repo-relative; optional scanners are only looked up, never executed here; a match is resolved to its final path (links and junctions followed, `\\?\` removed) and refused when it or a directory above it is the repository or the working directory by file identity | ✅ parsing (#85), Flask/FastAPI routes, sinks and auth (#86), fail-closed `DynamicArg` (#185), vendor and generated code listed as ignored (#88), Express routes, sinks and middleware auth in JS and TS (#87), optional scanners detected on `PATH` and never run, matches in the repository refused (#10, ADR 0010), final-path refusal (#221, ADR 0013) |
| `scanrun` | Runs gitleaks and osv-scanner offline and reads their reports | The only product package allowed `os/exec` (`execAllowedExact`, no subpackages); runs only the final path `static` resolved, re-checked outside the repository, and only an `.exe` on Windows; fixed arguments, no shell, offline flags, creep's own tool config; empty `PATH`, fresh `HOME`/`TMP`/cwd, proxies at a closed loopback port, no keys; timeout, byte and finding caps; output decoded into closed structs, paths inside the repository, everything else hashed; any failure is `failed`, never partial; gitleaks with a root `.gitleaksignore` is `failed` without starting; osv-scanner runs with `--no-ignore`; a timeout kills the process group on Unix; semgrep and osv-scanner without a usable local database are not run | ✅ (#221, ADR 0013) |
| `calibrate` | Seeded tasks, per-class score, tier, 30-day cache | Same seed gives the same tasks; runs through gateway | ✅ task generator (#89), per-class Wilson score, probes and tier (#90), 30-day cache per model and task set, `--recalibrate`, report header line (#91) |
| `planner` | Hypotheses from IDs and enums | **Never receives repository text** (no import of `reader`, `redact`, `static`; the caller copies `static.Graph` and the tier into `planner.Input`); output is a closed schema of IDs and enums; every sink is planned or skipped with a closed reason; ranking is deterministic, with no model call; the plan fits the token budget and the tier's step bound (S 32 and no literal-argument sinks, M 256, L 1024) | ✅ #12 |
| `reader` | Quarantined reading, closed output schema | Output never flows to planner as text: the planner gets only `Signal` (IDs, enums, numbers, and `Partial` for a verdict from a cut slice) | ✅ prompts and schema (#92, #93), slices from redacted files (#94), `Evaluate` and replay fixtures per testdata app (#95) |
| `report` | SARIF, JSON (`schema_version`), Markdown, coverage, data handling from `egress.log` | Every class is covered, partial or not evaluated; every optional scanner is listed with its classes, evaluated only when it ran; every not-scanned file is listed; an incomplete run is never clean; repository strings escaped | ✅ (#14, #175) |
| `sandbox`, `verify` | Container runtime, internal network, PoC runs | No internet; never on the host | ⬜ v0.2 |
| `mcp` | Read-only MCP server | No sandbox, no writes | ⬜ v0.3 |
| `cli` | Commands and flags (`flag`, no framework); `scan` wires calibrate → static → planner → reader → report, `why` reads the last JSON report; `estimate` measures the requests a scan would send; `--stats` counts what it spent | Unimplemented commands fail closed; the only place static, calibrate and reader values are mapped to planner values, by explicit switch; an incomplete or partial scan never exits 0 (ADR 0007, ADR 0009), and an enabled scanner that failed makes it incomplete (ADR 0013); `estimate` has no transport (its send function measures and refuses every request; ADR 0011); tests never reach a real model | ✅ `scan`, `why` (#175), `estimate`, `--stats` (#15); ⬜ `init`, `doctor`, `resume` continuation |

`planner` and `reader` must never import each other. This prompt-injection boundary is the one with the highest stakes in the layering.

## 4. Stable contracts

These follow semver once v1.0 ships. Before then, any change needs a note in the PR and, if the change breaks a contract, an ADR.

| Contract | Where | Versioning |
|---|---|---|
| CLI flags and exit codes | `cli`, `exitcode` | semver |
| Config and policy schema | `config` | `version:` key |
| JSON report | `report` | `schema_version`; schema in `docs/schemas/report-vN.json`; v1 amended additively before the first release (ADR 0009) |
| SARIF | `report` | SARIF 2.1.0 |
| Run state (JSONL) | `state` | per-line `v` |
| `egress.log` line | `gateway` | additive fields only |
| HTTP model contract | `models` | OpenAI-compatible + Anthropic |
| Command model contract | `models` | stdin prompt, stdout JSON |
| Recipes, presets, language kits | `recipes/`, `presets/`, kits | own `version:`; data, not code |
| Prompts | `prompts/` in the package that sends them: `internal/reader/prompts/` (one variant per tier S/M/L), `internal/calibrate/prompts/` (one variant, since calibration runs before a tier is known); the reader user turn (`HYPOTHESIS` line, numbered `CODE` lines, truncation notes) is built by `internal/reader/render.go` within `sliceBudget` per tier | `PromptVersion` per package; token-budget test (`prompts_test.go`) |

## 5. Extension points

Contributors add **data**, not core code:

- **Presets** (`presets/*.yaml`): command lines for model CLIs. They are community-owned because they track third-party flags.
- **Recipes** (v0.3): source, sink and hint records with fixtures, pinned by commit in `creep.lock`.
- **Language kits**: grammar WASM + sources/sinks + PoC templates + vulnerable/safe fixtures. A kit enters only if its conformance test passes. v0.1 ships Python and JS/TS only.

## 6. Maintainability matrix

Evidence from 2026-11-13 (lines are source/test, churn is commits on `main`).

| Component | Size | Churn | Open follow-ups | External load | Decision |
|---|---|---|---|---|---|
| `redact` | 1593 / 2565 | 3 | ~10 | none | **Simplify.** Freeze features after v0.1. Pin perf budgets with CI benchmarks. Close follow-ups in batches, not one per PR. |
| `gateway` | 1671 / 2008 | 4 | 6 | Go `net/http` | **Keep.** Freeze the exported API after #84. Use a `go/types` API guard (#115). |
| `tools/budget` | 1188 / 779 | 5 (highest) | 6 | none | **Trim.** The layer rule (#119) replaces ad-hoc import checks. The net source line count may not grow. |
| `config` | 860 / 657 | 3 | 3 | YAML | **Keep.** |
| `cli` | 727 / 655 | 3 | 1 | none | **Keep.** |
| presets (#7) | — | — | — | CLI flags change often | **Defer to the community.** The core keeps only the two contracts. |
| `static` grammars | — | — | — | grammar releases | **Kits with a conformance test.** No third language before v1.0. |
| `calibrate` templates | — | — | — | none | **Keep** (core differentiator). Templates are versioned data. |
| Agent loop | — | — | 14 Lows in one day | — | **Adjust.** The pentester runs per release ([ADR 0004](adr/0004-pentester-per-release.md)), and the auditor groups Lows per component in one living issue. |

## 7. Non-goals

- No `--url` and no scanning of targets that `creep` did not build from local source.
- No server, no telemetry, no "enterprise edition".
- No provider SDKs in the core, and no framework for the CLI.
- No languages beyond Python and JS/TS before v1.0.
- No automatic application of fixes.

## 8. Engineering principles

The developer follows these and the auditor checks every PR against them ([ADR 0005](adr/0005-auditor-architecture-review.md)). They are defaults, not rules to force: a deviation with a stated reason is fine.

- **Patterns** only where they remove real duplication or coupling. Name the problem first; never add a pattern for its own sake.
- **Modularity.** Small packages with one reason to exist (`doc.go` says which). Deep modules: a narrow exported API hiding real work. The layer table in §3 is respected.
- **Testing where it is needed.** New behavior is covered through its edge cases, failure paths and security protections, not trivial happy paths or getters. No test that only restates the implementation. Table-driven; model behavior gets a replay fixture.
- **Scalability and reuse.** Reuse an existing package before adding one. Work per input is bounded: linear time, capped size, and a documented worst case backed by a benchmark. No speculative abstraction.
- **SOLID the Go way, not forced.** Small interfaces declared by the consumer, composition over inheritance, dependencies passed in explicitly (no globals, no init-time wiring).
- **Paradigm mix.** Plain functions and data first; methods on a type when it owns state. Concurrency and parallelism only when they measurably help (I/O fan-out, CPU-bound batches), always bounded and cancellable through `context`.

## 9. Fitness functions

Automated checks that guard an architectural property. A new property needs a check here, not only prose. Atomic checks run on every PR; the per-version review (ADR 0005) is the holistic one.

| Property | Check | Where it runs |
|---|---|---|
| Only `gateway` reaches the network (invariant 1) | Net/exec/syscall import and reach rules, `internal/tools/budget/imports.go`, `reach.go`; depguard as editor feedback | `make budget`, CI `budget` and `lint` |
| No dependency without an ADR (invariant 6) | Dependency allowlist vs `docs/adr/dependencies.txt`, `go mod tidy -diff` | `make check`, CI `budget` |
| Small, auditable build | Module-graph and release-binary caps; no non-Go sources, `go.work`, `vendor/` or local replace | `make budget` |
| Small files | Go file cap of 400 lines, build-tagged files included (`lineProblems`) | `make budget` |
| Agent loop cannot erode | Pinned policy phrases in AGENTS.md, CONTRIBUTING.md, PR template (`policy.go`) | `make budget` |
| Workflows are pinned and safe | Immutable action/image pins, no `pull_request_target`; actionlint, zizmor | `make budget`, CI |
| Secrets never leave unredacted | Redaction leak tests (`redact/*_test.go`, escaped and percent-encoded webhook URLs in `encoded_test.go`; the every-offset key tests try every 11th offset under `-race` and every offset in the `windows-latest` job, #203), gateway fragment scan test, reader slice tests: a slice masks a secret that only whole-file redaction finds (`reader/slice_test.go`) | `make check` |
| Reader slices fail closed and keep repository text as data | Unreadable and redact-rejected files are listed as not scanned; `ErrRunFull` stops the run as incomplete; lines out of range are refused, and a file whose lines redaction shifted is listed as not scanned; every repository line sits behind its number with control, format and separator runes escaped, so none can fake a code line or header; the slice budget holds after escaping (`reader/slice_test.go`, `render_test.go`, `flow_test.go`) | `make check` |
| Model spend is bounded | Over-budget and concurrent-overspend tests, AIMD table test (`gateway/budget_test.go`, `aimd_test.go`; race on Linux CI) | `make check` |
| Redaction stays linear | `TestRedactLargeInputIsBounded`, `TestDenseKeysKeepCodeVisible`, `TestFindTotalMasksRest`; `Benchmark*` in `internal/redact` | `make check`; benchmarks at the per-version review |
| No known-vulnerable code or leaked secret | govulncheck, gitleaks over full history, CodeQL | CI |
| Vulnerable fixtures stay data and stay accurate | `internal/tools/testapps`: every `testdata/apps` app has a safe twin, holds only source files (no manifests, lockfiles or scripts), stays under 200 lines, and its `expected.json` matches the real lines; no Makefile, workflow, script or program-starting Go code names the apps | `make check` |
| Run-state JSONL stays additive (contract `v`) | Committed v1 fixtures decode with unknown fields disallowed (`TestV1FixtureDecodes`, `internal/state/testdata/v1`) | `make check` |
| JSON report contract holds (`schema_version`) | A committed fixture per released version (`internal/report/testdata/contract/vN.json`) validates against `docs/schemas/report-vN.json`; the current one decodes with unknown fields disallowed; fresh output validates too (`contract_test.go`, `golden_test.go`) | `make check` |
| SARIF stays valid for code scanning | Output validates against the committed official SARIF 2.1.0 schema, no network (`TestSARIFValidatesAgainstOfficialSchema`) | `make check` |
| State shipped in a scanned repo is never trusted | Planted cache entries and run logs are never served or read as complete (`internal/state/trust_test.go`) | `make check` |
| Package map stays current | `internal/tools/pkgmap -check`: `docs/map.md` lists every package from `go list ./...` with its `doc.go` first sentence and layer; a package without `doc.go`, a package comment or a layers row fails, and so does a map that differs from a fresh one (`internal/tools/pkgmap/main_test.go`, `render_test.go`) | `make check`, CI `test` |
| Layer table holds | `layers` block in §3: every module package has a row and imports only lower layers its row lists (`layers.go`) | `make budget`, CI `budget` |
| Calibration is reproducible and labels hold | Golden hashes per seed; every task keeps its twin marker, sink line and label; templates refuse aliasing renames (`calibrate/generate_test.go`, `templates_test.go`) | `make check` |
| Reader replays every testdata app to its expected verdicts | `reader/testdata/replay/<app>` holds one `state` cache recording per hypothesis; every app's vulnerable and safe variants replay through `Slicer.Build` and `Evaluate` with no network or key to the verdicts `expected.json` implies; every reader-class finding has a hypothesis and a safe twin; missing, torn, edited, foreign-signed or stale recordings and wrong answers fail (`replay_test.go`, `replay_fail_test.go`); regenerate with `go test ./internal/reader -run TestAppsReplay -update` | `make check` |
| A recorded calibration gets the same tier | Replay fixture `calibrate/testdata/replay/seed1_tier_m.json` pins scores and tier; tier thresholds compared exactly (`run_test.go`, `tier_test.go`, `score_test.go`); calibration calls go through `egress.log` with redaction (`egress_test.go`) | `make check` |
| Planner-facing route graph holds no repository text | No type reachable from `static.Graph` can carry text; hostile names never reach the serialized graph; markers planted in every text position of each `testdata/apps` fixture and the TypeScript Express fixture never reach any planner-facing form of its graph; fixture graphs are golden and match `expected.json` (`internal/static/extract_test.go`, `jsextract_test.go`, `extract_fixture_test.go`, `planner_text_test.go`, `jsplanner_text_test.go`) | `make check` |
| Static hints fail closed and nothing is silently skipped | Any non-constant or unmodeled binding (branches, try, tuple targets, loops, with, walrus, parameters, nested headers, lists changed in place; for JavaScript also destructuring, closures, `with`, `eval` and a cut handler scan) makes a sink `DynamicArg`; Express auth is never claimed from a `use` after the route, auth after the handler, a dynamic guard path or an ambiguous (reassigned or same-scope) receiver, and each mount of a router keeps its own auth; every middleware and handler of a route is scanned, method sinks on receivers from repository modules match like variables, and an entry or call outside the file or an escaped mounted router marks the route `Partial`; vendor, generated and minified files keep a `File` entry with their `Ignored` reason; loose generator wording, strings and docstrings never mark a file generated; absolute paths are refused (`internal/static/pybind_test.go`, `jsbind_test.go`, `jslimits_test.go`, `jsextract_test.go`, `jsstack_test.go`, `jsmodules_test.go`, `ignore_test.go`) | `make check` |
| Parser stays sandboxed and pinned | Embedded grammars match `SHA256SUMS`; modules import only the allowlisted WASI calls; hostile records and over-limit files fail closed (`internal/static/grammar_test.go`, `parser_test.go`, `tree_test.go`) | `make check` |
| A cached calibration is never stale or planted | Expiry boundaries, key on model, endpoint, seed and task set, corrupt, planted, re-tiered and newer-version files (`calibrate/cache_test.go`, `state/calibration_test.go`, v1 fixture `state/testdata/v1/calibration.json`) | `make check` |
| Prompts stay within their token budget | System prompt plus schema per reader tier, plus the largest slice against `sliceBudget` and the whole call per tier, and plus the largest user turn per calibration call kind, against `promptBudget` (`reader/prompts_test.go`, `reader/render_test.go`, `calibrate/prompts_test.go`) | `make check` |
| Scan never reads as clean when coverage is partial | Table tests through the CLI: `run_full`, `send_failed`, `budget`, step-cap decoys, planner token budget, inconclusive and invalid answers, a partial slice, NoSQL sinks of the Express testdata app pending planner support (`unmapped_kind`, #212), unsupported files (source languages with no grammar: a Go-only repository, a Flask repository plus one `.php` file whose Flask findings are still reported), syntax-error and refused (`a:b.py`) files each exit 4 with the incomplete mark and the files listed, also over the gate; complete runs exit 0 or 1; vendor files and tier S low-risk skips stay by design; `planner.ErrInput` fails closed; a recorded run replays to the same output and exit code with zero model calls (`internal/cli/scan_test.go`, `scan_replay_test.go`, `walk_test.go`) | `make check` |
| Optional scanners run only safely, and never silently | Only `internal/scanrun` may import `os/exec` (exec rule above). Detection refuses a match whose final path is in the repository or the current directory, through links, junctions, cycles and `\\?\` paths, and a relative entry; the runner starts nothing for semgrep, osv-scanner without a usable local database, gitleaks with a root `.gitleaksignore` (failed), a binary or database in the repository, or a `.cmd`; a helper dies with a timed-out scanner on Unix (`proc_unix_test.go`); a fake scanner (the test binary re-run) proves the child gets no key, proxy or `PATH` and the offline flags, and that malformed, missing, oversized, out-of-repository or too many results, a timeout and a bad exit status are `failed`; a failed scanner makes `creep scan` exit 4, the other states exit 0 with each scanner and its classes listed; the project file cannot enable a scanner (`internal/static/scanners_test.go`, `scanners_windows_test.go`, `internal/scanrun/run_test.go`, `run_windows_test.go`, `internal/config/scanners_test.go`, `internal/cli/scanners_test.go`, `scanners_run_test.go`) | `make check`, CI `windows` |
| Planner mappings stay exhaustive | Every `static.SinkKind`, `static.Methods` bit, `calibrate.Tier` and `reader.Class` maps by explicit switch, and every value the planner accepts is reached, so a value added on either side fails (`internal/cli/plannermap_test.go`) | `make check` |
| `creep why` and scan output keep repository text inert | IDs checked against the report pattern before any read; a planted or edited `.creep/report.json` is refused or printed escaped; hostile file names are escaped in scan output (`internal/cli/why_test.go`, `scan_test.go`, `internal/report/read_test.go`) | `make check` |
| Planner input and output hold no text (invariant 3) | No string, byte or rune sequence, map, interface, func, chan or float is reachable from `planner.Input` or `planner.Plan`, and `Build` takes only `Input`; unknown enums, duplicate or dangling IDs and oversized input are rejected; the plan fits the budget and step bound, ranks highest risk first and covers every sink (`planner/text_test.go`, `input_test.go`, `plan_test.go`) | `make check` |
| Reader output never reaches the planner as text (invariant 3) | No string, byte or rune sequence, map, interface, func or chan is reachable from `reader.Signal`; hostile replies (unknown fields, trailing text, out-of-range or overlapping lines, huge numbers) are rejected (`reader/signal_test.go`, `output_test.go`) | `make check` |

Function length has no automated check; the auditor reviews it.

## 10. Evolutionary architecture

Adapted from *Building Evolutionary Architectures* (Ford, Parsons, Kua), taking only what fits a single-binary CLI with one maintainer.

| Book idea | How creep adapts it | Not adopted |
|---|---|---|
| Fitness functions | The checks in §9, in one table; add one only when a property has no automated guard | No fitness-function framework or dashboard |
| Atomic vs holistic, triggered vs continual | Atomic and triggered: `make check` and CI on every PR. Holistic: the per-version review (whole diff, benchmarks over time) | No production monitoring (no telemetry, invariant 5) |
| Incremental change | Small issues, up to three features in flight in different packages ([ADR 0006](adr/0006-three-features-in-flight.md)), squash merges, sub-issues for L | — |
| Appropriate coupling (connascence) | Layer table and narrow interfaces; the auditor flags strong connascence across a package boundary | No coupling metrics tooling |
| Anticorruption layer | Model contracts translate vendor output into closed schemas before planner or reader see it | — |
| Last responsible moment | ADRs only when a dependency or public contract changes | — |
| Evolvability over predictability | Prefer data (prompts, rules, kits, layer table) over code so changes stay local | No speculative plugin systems |

Skipped on purpose: architectural quanta per service, cross-service schema evolution and per-team deployment pipelines. They target distributed systems; creep is one binary with no server.

## ADR index

| ADR | Decision |
|---|---|
| [0001](adr/0001-yaml-parser.md) | `go.yaml.in/yaml/v3` for config |
| [0002](adr/0002-agent-loop-scope.md) | Shared context in the agent loop; pentester independent |
| [0003](adr/0003-architecture-layers.md) | Layers, stable contracts, maintainability decisions, module path |
| [0004](adr/0004-pentester-per-release.md) | Pentester once per version and on external PRs |
| [0005](adr/0005-auditor-architecture-review.md) | Auditor reviews PRs against this document; per-version architecture review |
| [0006](adr/0006-three-features-in-flight.md) | Up to three features in flight, each with its own loop |
| [0007](adr/0007-exit-code-incomplete.md) | Exit code 4 for incomplete runs |
| [0008](adr/0008-wazero-tree-sitter.md) | wazero runs tree-sitter grammars built to WebAssembly; pinned artifacts and sandbox limits |
| [0009](adr/0009-scan-and-why-contract.md) | `creep scan` and `creep why` contract: report location, incompleteness rules, gate severities, report v1 additions |
| [0010](adr/0010-optional-scanners-detect-only.md) | Optional scanners are detected on `PATH`, not run; `coverage.scanners` lists each with its classes |
| [0011](adr/0011-estimate-and-stats.md) | `creep estimate` (no model or network call), `--stats`, `--price-in`/`--price-out` |
| [0012](adr/0012-language-kits.md) | Language kits as data: `.scm` queries in a Go matcher over the validated tree, closed sink tables, embedded-only loading; semantics and fail-closed rules stay in Go |
| [0013](adr/0013-scanner-runner.md) | `internal/scanrun` alone may start programs: gitleaks and osv-scanner offline, fixed arguments, final path outside the repository; a failed scanner makes the run incomplete; the project file may only remove scanners |
