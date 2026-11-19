# ADR 0017: Language-agnostic analysis

- **Status:** Accepted (maintainer approval on #265, 2026-11-19)
- **Date:** 2026-11-19
- **Deciders:** @Ludocius
- **Supersedes:** [ADR 0012](0012-language-kits.md) now. [ADR 0008](0008-wazero-tree-sitter.md) is superseded when step F of #265 lands, not before: until then wazero and the grammars still run for Python and JS/TS.
- **Amends:** [ADR 0009](0009-scan-and-why-contract.md) (incompleteness rules and not-evaluated reasons, from step D; see [Report contract](#report-contract-d3)), architecture §3, §5, §6, §7 and §9.
- **Changes:** a new layer-4 package `internal/discover`; what `creep scan` and `creep estimate` send to the model (whole redacted source files, D1); when a run may exit 0 (D2)

## Context

Issue #265. `internal/static` holds about 3,000 lines of hand-written Go for Flask, FastAPI and Express, plus about 4.2 MB of tree-sitter grammars run in wazero (ADR 0008). A source file in any other language is listed as `unsupported_language`, so a Go, PHP, Java or Ruby repository always exits 4. ADR 0012 planned language kits as data (#217), but kits still need a grammar per language, a semantics module per language family and a query matcher to maintain. Architecture §6 rates language support "Costly" either way.

What sets creep apart is already language-neutral: calibrating the model per class, choosing a strategy per tier, declaring what was not evaluated, and verifying by execution in the sandbox. `planner`, `reader`, `calibrate` and `report` carry no language data today (`planner.Input`, `reader.Target`).

The design evidence still holds: a model detecting alone does poorly on realistic data. A code model that scored 68% F1 on an older benchmark scored 3% on PrimeVul's realistic split (Ding et al., 2024). So the model must review deterministic candidates and must not decide alone what gets reviewed.

Constraints: invariants 1 to 6 (AGENTS.md); report JSON v1 is released with v0.1.0, and ADR 0009 says fields change only with a `schema_version` bump from the first release on; no new direct dependency; replay with no network (`--record`/`--replay`) must keep working.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Per-language Go in `internal/static` (today) | Precise for the three frameworks it knows; deterministic | Cost grows with every language and framework; needs Go and AST skills; everything else exits 4 |
| B. Language kits as data (ADR 0012) | No Go per framework; bounded matcher | Still one pinned grammar per language (ADR 0008 build), a semantics module per family, and a query matcher and kit schema to maintain; a language without a kit still exits 4 |
| C. opengrep or semgrep as the extraction engine | Many languages; mature rules | **Rejected.** An external engine creep must run on hostile input (ADR 0013 rules, a new exec path); semgrep's maintained rules are under the Semgrep Rules License, whose terms are incompatible with redistributing them inside an Apache-2.0 binary; it returns findings, not the entry-point and sink candidates the planner needs (ADR 0012 option D) |
| D. Model only: the model reads the repository and reports vulnerabilities | No per-language work at all | **Rejected.** 68 → 3% F1 on realistic data (above); no deterministic floor, so one prompt injection in the repository can hide everything; nothing to measure coverage against |
| E. Language servers (LSP) or ctags for symbols | Many languages; real symbol tables | **Rejected.** Language servers load the project to answer (build files, `go list`, Gradle and Maven plugins, `node_modules` hooks), which runs code the repository chose (A4, invariant 4); universal-ctags is GPL-2.0; both are external programs per language |
| F. **Inventory + lexical tripwire + model discovery, combined by union only** (chosen) | No per-language code; every inventoried source file is read; a deterministic tripwire the model cannot remove; worst-case flags keep model output from lowering risk; replayable | Whole redacted files leave the machine (D1); recall depends on the model and on the tripwire table; the live gate is nondeterministic (replay is not); quality must be measured again (#204, #35) |

## Decision

**Option F.** What decided it: it is the only option that evaluates any language without adding per-language code, an external engine or a new exec path, while keeping a deterministic floor (the tripwire) that the model can add to but never remove from.

creep becomes language-agnostic: no per-language code, no language kits, no external language engines. What the repository contains is detected when it is scanned:

1. **Inventory** (deterministic, local): each file is classified by name and bytes into a source language, a manifest, a container file or nothing, from one generic table ([Inventory table](#inventory-table)).
2. **Lexical tripwire** (deterministic, local): one cross-language table of sink signatures is matched on the bytes of each source file, with no parser ([Tripwire table](#tripwire-table)). Each hit is a candidate.
3. **Model discovery** (`internal/discover`, through the gateway): the model reads whole redacted source files and proposes entry points, sinks and auth as line spans and enums ([Discovery schema](#discovery-schema)). creep validates each proposal against the file and assigns every ID itself.
4. **Union**: tripwire candidates, discovery proposals and, until step E, today's static graph are merged by union. Then the planner and reader run as today.

### Decisions D1–D5 (maintainer, 2026-11-19)

- **D1 Egress.** Discovery sends whole redacted source files, not slices. Each file goes through `redact.File` and then the gateway like every other call: consent per endpoint (unchanged), token budget, write-ahead `egress.log` line and payload file. `creep estimate` counts discovery requests next to reader requests (ADR 0011 option B: the requests are built and measured, never sent). The docs recommend a local model (loopback endpoint or a command model) for sensitive code. A file whose redacted text does not fit one discovery call at the tier's budget is listed `too_large`; files are never split, so a large file is a gap, not a partial read.
- **D2 Exit 0.** A run may exit 0 only when:
  - every inventoried source file was read in full by discovery,
  - every discovery canary was found,
  - every tripwire candidate was evaluated.

  Otherwise the run is incomplete and exits 4, together with ADR 0009's existing rules (early stops, skipped sinks, partial slices). A targeted injection that hides one entry point from the model is an **accepted residual**. It is mitigated by the union with the tripwire, by the worst-case flags and by sandbox verification, and the threat model states it (R19).
- **D3 Report.** JSON stays `schema_version` 1. See [Report contract](#report-contract-d3) for the exact outcome.
- **D4 Removal gate.** See [Removal gate](#removal-gate-d4).
- **D5 Calibration.** Calibration templates stay Python and JS. They measure the model per vulnerability class, which does not depend on the scanned language. Generating them in the detected language is a follow-up issue, not part of #265.

### Union only, forced worst-case flags

Discovery and the tripwire are combined by union. Neither can remove a candidate, and neither can lower one's risk:

- Every sink from a discovery proposal or a tripwire hit reaches `planner.Input` with **`DynamicArg = true`, `Parameterized = false` and `Indirect = false`**, and its entry point with **`Authenticated = false`** and every method bit set (the planner ranks write methods higher, so a method list from the model could lower a route's rank; the schema has none). These are the planner's highest-risk values. Flags that lower risk are never set from model output, and the tripwire cannot compute them.
- A tripwire hit or sink proposal outside every proposed entry point's span is attached to one synthetic entry point per file (all methods, not authenticated), so it is planned, never dropped for lack of a route.
- When two sources name the same file, line and kind, they become one candidate whose flags take the higher-risk value of each (`DynamicArg` if any says so, `Parameterized` and `Authenticated` only if all say so). Until step E, a static sink at the same place as a model proposal can therefore only gain risk from the merge.
- Auth spans a model proposes may only widen the reader's slice. They never set `Authenticated` and never skip a sink.
- The planner still receives only IDs, enums and booleans (invariant 3). Spans and paths stay in the mapping in `internal/cli`, as static locations do today.

### Discovery schema

The discovery reply is a closed schema, decoded by `models` with unknown, duplicate and case-variant keys refused (as for the reader):

| Field | Type | Rule |
|---|---|---|
| `entries[]` | `{start, end, kind}` | `start ≤ end`, both inside the file's lines; `kind` is a closed enum (`http`, `rpc`, `message`, `cli`, `scheduled`, `other`); it never changes planning |
| `sinks[]` | `{line, kind, entry}` | `line` inside the file and not blank; `kind` one of the planner's sink kinds (`sql`, `nosql`, `shell`, `file`, `http_client`, `template`); `entry` an index into `entries` or `-1` |
| `auth[]` | `{start, end}` | inside the file; widens the slice only (above) |

- The reply holds **no free text**: no names, paths, IDs or explanations. Line numbers refer to the redacted file creep sent; a line redaction shifted is handled as the reader does today (`lines_shifted`).
- creep validates every proposal against the file bytes and assigns route and sink IDs itself, in a deterministic order (path, then line, then kind). IDs never come from the reply.
- Any invalid proposal makes the whole reply invalid. After the bounded retries `models` already does, the file is listed `parse_failed`: creep could not extract a trusted structure from it.
- Caps per file (initial values, fixed with a benchmark in step B): 256 entries, 1,024 sinks, 256 auth spans. A reply at a cap marks the file `truncated` (incomplete), never silently cut.
- Prompts live in `internal/discover/prompts/`, one variant per tier with a token-budget test (AGENTS.md conventions). The prompt may name the inventory's language ID (an enum) as a hint.

### Discovery canary

Each discovery call (a batch of one or more files) carries one synthetic file creep generates from a seeded template: an entry point with a sink at lines creep knows, with random names and a random place in the batch. The file holds no repository text. If the reply does not report an entry covering the canary's entry line and a sink at its sink line, the batch is incomplete: every file in it is listed `parse_failed` and the run exits 4. Canary proposals are removed before the union. The seed comes from the run, so `--record`/`--replay` reproduce the batch byte for byte.

The canary proves the model followed the instructions for that batch. It does not prove the model saw every real entry point: a targeted injection can tell it to report the canary and hide one route (R19, accepted residual).

### Cache

Discovery replies are cached content-addressed, in the user cache directory (`<user cache dir>/creep/discover/`, directories 0700, files 0600), **never in the repository or `.creep`**. The key is the SHA-256 of the prompt version, the schema version, the model identity (contract, endpoint, name), the tier and the redacted file bytes. An entry is written only from a batch whose canary was found, holds only spans and enums, and is signed with the per-user state secret like run state (A7). A missing, unsigned, malformed or foreign entry is a live miss, never served (the #160 rule). Entries expire with `calibration.cache_days`. `--record`/`--replay` keep using the run-state cache in `.creep/cache`; the discovery cache only saves repeated calls between runs.

### Inventory table

One generic table, data in `internal/discover`, matched by file name and bytes only. It reports IDs and enums (language, manifest, container); it never chooses an analysis path. It replaces the closed extension list in `internal/cli/sourceext.go`.

| Kind | Matched by | Entries (initial) |
|---|---|---|
| Source language | Extension (lowercase) | Python `.py`; JavaScript `.js .mjs .cjs .jsx`; TypeScript `.ts .mts .cts .tsx`; Go `.go`; PHP `.php .phtml`; Java `.java .jsp`; Kotlin `.kt .kts`; Scala `.scala`; Groovy `.groovy`; Clojure `.clj`; Ruby `.rb .erb`; C# `.cs .cshtml .razor .aspx`; VB `.vb`; F# `.fs`; Rust `.rs`; Elixir `.ex .exs`; Erlang `.erl`; Swift `.swift`; Dart `.dart`; Perl `.pl .pm`; Lua `.lua`; C and C++ `.c .h .cc .cpp .cxx .hpp`; Vue `.vue`; Svelte `.svelte`; ColdFusion `.cfm` |
| Source language | First line `#!` of an extensionless file | `python`, `node`, `ruby`, `perl`, `php` interpreters |
| Manifest | Exact file name | `package.json`, `go.mod`, `pom.xml`, `build.gradle`, `build.gradle.kts`, `requirements.txt` and `requirements*.txt`, `pyproject.toml`, `Pipfile`, `Gemfile`, `composer.json`, `Cargo.toml`, `*.csproj`, `mix.exs` |
| Container | Exact file name | `Dockerfile`, `*.dockerfile`, `Containerfile`, `compose.yaml`, `compose.yml`, `docker-compose.yaml`, `docker-compose.yml` |
| Not source | Bytes | A NUL byte in the first 8 KiB (binary) |

- Every source file is read by discovery and scanned by the tripwire. A file the table does not name is not source, is not read and is not listed, as ADR 0009 says today; adding an extension is a reviewed data change.
- Manifests and container files are recorded for the sandbox build (#23) and the report text; they are not sent to discovery unless they are also source.
- Vendor, generated and minified files keep ADR 0009's evidence rules (follow-up P4, #213, step A): believed only with their mark, and otherwise read like first-party code. "Parsed without errors and holds no route" becomes "read in full by discovery with no proposal and no tripwire hit" at step D.

### Tripwire table

One cross-language table of sink signatures, kept as data (`internal/discover/tripwire.tsv`, embedded): one row per signature with its sink kind and at least one fixture line that must match. Matching is a byte search over the redacted file: case-sensitive, the signature preceded by a byte that cannot be part of an identifier, comments and strings included (there is no parser, so it over-matches on purpose; the reader discards what is not a sink). Each hit is the sink's line.

| Kind | Example signatures (initial) |
|---|---|
| `sql` | `execute(`, `executemany(`, `executescript(`, `.raw(`, `.query(`, `Query(`, `QueryRow(`, `Exec(`, `executeQuery(`, `executeUpdate(`, `createQuery(`, `createNativeQuery(`, `mysqli_query(`, `pg_query(`, `find_by_sql(`, `FromSqlRaw(`, `ExecuteSqlRaw(` |
| `nosql` | `.find(`, `.findOne(`, `.aggregate(`, `$where`, `.updateOne(`, `.deleteMany(` |
| `shell` | `system(`, `popen(`, `subprocess.`, `child_process`, `execSync(`, `spawn(`, `exec.Command(`, `Runtime.getRuntime().exec(`, `ProcessBuilder(`, `shell_exec(`, `passthru(`, `proc_open(`, `Process.Start(`, `Command::new(`, `%x(` |
| `file` | `open(`, `send_file(`, `sendFile(`, `readFile(`, `createReadStream(`, `os.Open(`, `os.ReadFile(`, `ServeFile(`, `file_get_contents(`, `fopen(`, `include(`, `new File(`, `Files.read`, `File.ReadAll`, `File.read(` |
| `http_client` | `requests.`, `urlopen(`, `httpx.`, `fetch(`, `axios`, `http.Get(`, `http.NewRequest(`, `curl_exec(`, `HttpClient`, `RestTemplate`, `WebClient`, `Net::HTTP`, `URI.open(` |
| `template` | `render_template_string(`, `Template(`, `from_string(`, `ejs.render(`, `template.HTML(`, `Handlebars.compile(`, `Velocity`, `ERB.new(` |

- The table has limits checked by a test: at most 512 rows, signatures of 2 to 64 bytes. Matching is linear in the file size times the table size, with a per-file cap of 1,024 hits; a file at the cap is `truncated`.
- Rows are tuned in step B against every `testdata/apps` app and its safe twin. Broad rows raise the number of reader steps; a decoy flood ends at the tier's step cap and is incomplete (ADR 0009, `step_cap`), never clean.
- A sink kind the planner does not have (code evaluation, deserialization) needs a new closed `planner.SinkKind`, which is a Go change on purpose, as in ADR 0009.

### Report contract (D3)

ADR 0009 fixed v1 additively **before** the first release and decided: "From the first release on, report fields change only with a `schema_version` bump, as the schema says." v0.1.0 is released (2026-11-17), so ADR 0009 does **not** allow new optional fields in v1 any more. The outcome:

- **JSON stays v1 and gains nothing.** No new field, no new value in the `not_evaluated.reason` enum. Discovery gaps reuse existing reasons: `too_large` (does not fit a discovery call), `read_failed`, `line_too_long`, `redact_failed`, `run_full`, `send_failed`, `budget`, `lines_shifted`, `parse_failed` (invalid reply or missed canary) and `truncated` (a per-file cap). `run.reason` is the first file or finding reason in ADR 0009's order, so it needs no new value either.
- `unsupported_language`, `syntax_error` and `no_routes` stop being emitted ([Migration](#migration)). They stay valid in the v1 schema, so older reports and the committed v1 fixture still validate.
- The inventory is printed in the text summary and the Markdown report only (neither is a versioned contract, architecture §4), the way `Report.NoRoutesIn` is kept out of JSON (`json:"-"`).
- If a later step needs the inventory, a canary outcome or any other new value in JSON, that is **report v2**: `docs/schemas/report-v2.json`, a committed v2 contract fixture next to v1, and its own ADR. #265 does not need it.

### Migration

At most three in flight, from different packages (ADR 0006). Today's behaviour is unchanged until step D.

| Step | What | Behaviour change |
|---|---|---|
| ADR | This ADR (docs only; auditor only) | None |
| A | The language-neutral parts of #255: `report/bydesign.go` and goldens; Go and PHP marks vouch for nothing; marks in exact case; the deduplicated by-design rule in `cli`. Closes #213 | By-design rules only |
| B | `internal/discover`: schema, per-tier prompts with a token-budget test, validation, canary, tripwire table, inventory, replay fixtures built from `expected.json`. Not wired into the scan | None |
| C | Move the language-neutral files of `internal/static` (`finalpath.go`, `scanners.go`, `ignore.go`, `vendorproof.go`) to a neutral package; update the layers table | None |
| D | Wire inventory, discovery and the tripwire into `creep scan` and `creep estimate`, unioned with today's static graph; amend ADR 0009's text | Files of other languages are read (no more `unsupported_language`); a Python or JS/TS file must complete both static and discovery; discovery egress starts (D1) |
| E | Pass the removal gate (D4), switch the default, delete the Flask, FastAPI and Express code, the route goldens and the route tests; rebuild `TestInputCarriesNoText` and the protections on the new path | `syntax_error` and `no_routes` stop; a repository with no candidate, read in full with every canary found, exits 0 with its readable classes covered |
| F | Drop wazero and the grammars: `dependencies.txt`, the budget net-reach exception for `internal/static`, ADR 0008 marked superseded | `go.mod` has one direct dependency (yaml/v3) |

### Removal gate (D4)

The static code is deleted (step E) only when both hold:

- discovery plus the tripwire find **100%** of the routes and sinks in every `testdata/apps/*/expected.json`, on replay fixtures with no network;
- the protection suite (`make protections`, architecture §9) is rebuilt without `internal/static` and every protection still has a broken fixture that proves it fails.

Until the gate passes, the static graph stays in the union, so recall can only grow.

## Consequences

- A Go, PHP, Java or Ruby repository is evaluated instead of exiting 4. New languages and frameworks need no Go code; the inventory and tripwire tables are reviewed data.
- After step F, about 3,000 lines of Go, the route goldens, 4.2 MB of grammars, the grammar build and wazero (with `golang.org/x/sys`) are gone; the binary shrinks and the budget net-reach exception goes away.
- `internal/discover` is a new layer-4 package (models, gateway, redact, state, config), next to `reader`. `planner` never imports it; `internal/cli` maps its output to `planner.Input` by explicit switch, as it maps static today.
- New fitness functions, added to architecture §9 with the code: model output never lowers a candidate's risk or removes a candidate; a missed canary makes the run incomplete; the discovery reply schema refuses free text; planner input holds no text on the new path; a planted or unsigned discovery cache entry is never served; `--record`/`--replay` reproduce a discovery run with no network; tripwire table limits hold, with a benchmark.

**Accepted residuals**

- **Targeted injection** (D2, R19). Repository text can steer the model to hide an entry point or a sink in one file while it still reports the canary. The tripwire still raises every signature it knows, the worst-case flags keep the rest at full risk, and sandbox verification (v0.2) checks what is found. A route with no tripwire signature that the model hides is missed, and the run can still exit 0.
- **Whole-file egress** (D1, R20). More of the repository leaves the machine than with slices: every inventoried source file, redacted. Consent, the allowlist, the budget and `egress.log` are unchanged; `creep estimate` shows the volume first; the docs recommend a local model for sensitive code.
- **Nondeterministic live gate.** Two live runs on the same commit can propose different candidates, so a live CI gate can differ between runs. Replay is deterministic, the cache makes repeated runs stable while it is valid, and the union keeps the tripwire and (until E) static as a floor.
- **Quality may drop until measured.** Precision and recall with a real small model are not measured yet (#204, benchmark #35 in v0.3). The removal gate covers only the testdata apps; until #35, findings on other languages carry the same `probable` status and calibration tier as today, and the README says so.
- Calibration stays Python and JS (D5), so the per-class tier is measured on those languages, not on the scanned one.
