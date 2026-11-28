# ADR 0017: Language-agnostic analysis

- **Status:** Accepted (maintainer approval on #265, 2026-11-19)
- **Date:** 2026-11-19
- **Deciders:** @Ludocius
- **Supersedes:** [ADR 0012](0012-language-kits.md) and [ADR 0008](0008-wazero-tree-sitter.md) (wazero and the grammars removed by #265 step F, landed with steps C–E in one PR; see [Amendments](#amendments-2026-11-19)).
- **Amends:** [ADR 0009](0009-scan-and-why-contract.md) (incompleteness rules and not-evaluated reasons, from step D; see [Report contract](#report-contract-d3)), architecture §3, §5, §6, §7 and §9.
- **Changes:** a new layer-4 package `internal/discover`; what `creep scan` and `creep estimate` send to the model (whole redacted source files, D1); when a run may exit 0 (D2)
- **Amended by:** [#366](#amendment-366-language-neutral-file-rules) (Accepted: every text file is read, vendor is what the repository ignores and git does not track, the marks read bytes only, recall rests on model discovery); [ADR 0037](0037-language-neutral-calibration.md) (Accepted: D5 superseded, calibration is one language-neutral pseudocode task set and no language is named as measured); [ADR 0034](0034-classes-not-looked-for.md) (Accepted: the tripwire rows for code evaluated from a string and objects decoded from bytes take the kinds `code_eval` and `deserialize` instead of `shell`); [ADR 0024](0024-discovery-stability.md) (`--stability N`: every batch is sent to N samples and their proposals join the union; a sample never removes a candidate, lowers its risk or clears a failure); [ADR 0009's #26 amendment](0009-scan-and-why-contract.md#amendment-26-2026-11-21-incremental-scans-with---changed): there is no report v2, so D3's "JSON stays v1 and gains nothing" becomes "v1 changes additively only"; v1 gains the `unchanged` reason.

## Context

Issue #265. `internal/static` holds about 3,000 lines of hand-written Go for Flask, FastAPI and Express, plus about 4.2 MB of tree-sitter grammars run in wazero (ADR 0008). A source file in any other language is listed as `unsupported_language`, so a Go, PHP, Java or Ruby repository always exits 4. ADR 0012 planned language kits as data (#217), but kits still need a grammar per language, a semantics module per language family and a query matcher to maintain. ADR 0012 itself rates per-language Go "Costly" (option A), and kits only move that cost into grammars and semantics modules.

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

- **D1 Egress.** Discovery sends whole redacted source files, not slices. Each file goes through `redact.File` and then the gateway like every other call: consent per endpoint (unchanged, so a consent stored before step D, in the consent store or a CI policy's consent list, also covers discovery's whole-file egress; see [Consent](#consent-for-whole-file-egress-d1)), token budget, write-ahead `egress.log` line and payload file. `creep estimate` counts discovery requests next to reader requests (ADR 0011 option B: the requests are built and measured, never sent). The docs recommend a local model (loopback endpoint or a command model) for sensitive code. A file whose redacted text does not fit one discovery call at the tier's budget is listed `too_large`; files are never split, so a large file is a gap, not a partial read.
- **D2 Exit 0.** A run may exit 0 only when:
  - every inventoried source file not left out by design (ADR 0009: vendor, generated and minified files with their evidence) was read in full by discovery,
  - every discovery canary was found,
  - every tripwire candidate was evaluated.

  Otherwise the run is incomplete and exits 4, together with ADR 0009's existing rules (early stops, skipped sinks, partial slices). A targeted injection that hides one entry point from the model is an **accepted residual**; its reach is the whole discovery batch, not only the injected file (see Accepted residuals). It is mitigated by the union with the tripwire, by the worst-case flags and by sandbox verification, and the threat model states it (R19).
- **D3 Report.** JSON stays `schema_version` 1. See [Report contract](#report-contract-d3) for the exact outcome.
- **D4 Removal gate.** See [Removal gate](#removal-gate-d4).
- **D5 Calibration.** Calibration templates stay Python and JS. They measure the model per vulnerability class, which does not depend on the scanned language. Generating them in the detected language is a follow-up issue, not part of #265.

### Union only, forced worst-case flags

Discovery and the tripwire are combined by union. Neither can remove a candidate, and neither can lower one's risk:

- Every sink from a discovery proposal or a tripwire hit reaches `planner.Input` with **`DynamicArg = true`, `Parameterized = false` and `Indirect = false`**, and its entry point with **`Authenticated = false`** and every method bit set (the planner ranks write methods higher, so a method list from the model could lower a route's rank; the schema has none). These are the planner's highest-risk values. Flags that lower risk are never set from model output, and the tripwire cannot compute them.
- A tripwire hit or sink proposal outside every proposed entry point's span is attached to one synthetic entry point per file (all methods, not authenticated), so it is planned, never dropped for lack of a route.
- When two sources name the same file, line and kind, they become one candidate whose flags take the higher-risk value of each (`DynamicArg` if any says so; `Parameterized`, `Authenticated` and `Indirect` only if all say so). Until step E, a static sink at the same place as a model proposal can therefore only gain risk from the merge.
- Auth spans a model proposes may only widen the reader's slice. They never set `Authenticated` and never skip a sink.
- The planner still receives only IDs, enums and booleans (invariant 3). Spans and paths stay in the mapping in `internal/cli`, as static locations do today.

### Discovery schema

The discovery reply is a closed schema, decoded by `models` with unknown, duplicate and case-variant keys refused (as for the reader). A batch holds the canary and one or more real files; creep numbers them `0..n-1` in the order it sends them, and every proposal names its file by that index:

| Field | Type | Rule |
|---|---|---|
| `entries[]` | `{file, start, end, kind}` | `file` an index creep assigned in this batch (an unknown index makes the reply invalid); `start ≤ end`, both inside that file's lines; `kind` is a closed enum (`http`, `rpc`, `message`, `cli`, `scheduled`, `other`); it never changes planning |
| `sinks[]` | `{file, line, kind, entry}` | `file` as above; `line` inside that file and not blank; `kind` one of the planner's sink kinds (`sql`, `nosql`, `shell`, `file`, `http_client`, `template`); `entry` an index into `entries` whose `file` is the same, or `-1` |
| `auth[]` | `{file, start, end}` | `file` as above; inside that file; widens the slice only (above) |

- The reply holds **no free text**: no names, paths, IDs or explanations. Line numbers refer to the redacted file creep sent; a line redaction shifted is handled as the reader does today (`lines_shifted`).
- creep validates every proposal against the bytes of the file its index names and assigns route and sink IDs itself, in a deterministic order (path, then line, then kind). IDs never come from the reply.
- Any invalid proposal makes the whole reply invalid. After the bounded retries `models` already does, **every file in the batch** is listed `parse_failed` (see [Report contract](#report-contract-d3) for the widened meaning).
- Caps apply **per file** (initial values, fixed with a benchmark in step B): 256 entries, 1,024 sinks, 256 auth spans for each file index. A file at a cap is marked `truncated` (incomplete), never silently cut; the other files of the batch are unaffected.
- Tripwire candidates from a file listed `parse_failed` or `truncated` are still planned (union); only the discovery side of that file is distrusted.
- Prompts live in `internal/discover/prompts/`, one variant per tier with a token-budget test (AGENTS.md conventions). The prompt may name the inventory's language ID (an enum) as a hint.

### Discovery canary

Each discovery call (a batch of one or more files) carries one synthetic file creep generates from a seeded template: an entry point with a sink at lines creep knows, with random names and a random place in the batch. The file holds no repository text. If the reply does not report an entry covering the canary's entry line and a sink at its sink line, the batch is incomplete: every file in it is listed `parse_failed` and the run exits 4. The text summary and the Markdown report name the cause for each such batch, for example `discovery canary not found: the model did not follow the instructions for this batch (3 files)`, so nobody looks for a syntax error in a file that is fine. Canary proposals are removed before the union. The seed comes from the run, so `--record`/`--replay` reproduce the batch byte for byte.

The canary proves the model followed the instructions for that batch. It does not prove the model saw every real entry point: a targeted injection in any file of the batch can tell it to report the canary and hide routes in **every file of that batch**, not only its own (R19, accepted residual).

### Cache

Discovery replies are cached content-addressed, in the user cache directory (`<user cache dir>/creep/discover/`, directories 0700, files 0600), **never in the repository or `.creep`**. The key is the SHA-256 of the prompt version, the schema version, the model identity (contract, endpoint, name), the tier and the redacted file bytes. An entry is written only from a batch whose canary was found, holds only spans and enums, and is signed with the per-user state secret like run state (A7). A missing, unsigned, malformed or foreign entry is a live miss, never served (the #160 rule). Entries expire with `calibration.cache_days`. `--record`/`--replay` keep using the run-state cache in `.creep/cache`; the discovery cache only saves repeated calls between runs.

### Consent for whole-file egress (D1)

D1 keeps consent per endpoint unchanged, so a consent given before step D (stored in the consent store, or listed in a CI policy) carries over to discovery: from step D the same endpoint receives every inventoried source file, redacted, with no new prompt.

| Option | Pros | Cons |
|---|---|---|
| A. Carry over, as D1 says, plus a notice | No new consent state; CI keeps working; matches the maintainer's D1 | An operator who consented to slices now sends whole files without being asked again |
| B. A separate discovery consent per endpoint (a second scope in the consent store and policy) | Informed consent for the larger egress | A second consent contract to keep; every CI job exits 2 until its policy is edited; contradicts D1 |

**Recommended: option A**, because D1 fixed it and the egress still goes only to an endpoint the operator allowlisted and consented to. Step D adds: a line on stderr at every scan start naming the endpoint and the number of whole files discovery will send (the `estimate` count, no model call); the same count in the Markdown data-handling section; and the `security` release-note label on the step D PR so operators see the change before they upgrade. Option B stays open if the maintainer revisits D1; it would need its own amendment.

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

One cross-language table of sink signatures, kept as data (`internal/discover/tripwire.tsv`, embedded): one row per signature with its sink kind and at least one fixture line that must match. Matching is a byte search over the redacted file: case-sensitive; when a signature starts with an identifier byte (a letter, digit or `_`), the byte before the match must not be one, so `open(` does not match inside `reopen(`; a signature that starts with any other byte (`.raw(`, `.find(`, `$where`, `%x(`) matches wherever it occurs, after an identifier included (`db.raw(`). Comments and strings included (there is no parser, so it over-matches on purpose; the reader discards what is not a sink). Each hit is the sink's line.

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

- **JSON stays v1 and gains nothing.** No new field, no new value in the `not_evaluated.reason` enum. Discovery gaps reuse existing reasons: `too_large` (does not fit a discovery call), `read_failed`, `line_too_long`, `redact_failed`, `run_full`, `send_failed`, `budget`, `lines_shifted`, `parse_failed` and `truncated` (a per-file cap). `run.reason` is the first file or finding reason in ADR 0009's order, so it needs no new value either.
- **`parse_failed` is widened**: today it means the parser hit a limit or failed; from step B or D it means "creep could not extract a trusted structure from this file": a parser limit, an invalid discovery reply, or a missed discovery canary in the file's batch. It is the only existing reason with that meaning (`send_failed` implies transport, `truncated` a cap, `read_failed` local I/O). The comment on `report.SkipParseFailed` changes with the code. Because the JSON value cannot say which cause applied, the text summary and the Markdown report (not versioned contracts) name it per batch, and a missed canary always by name.
- `unsupported_language`, `syntax_error` and `no_routes` stop being emitted ([Migration](#migration)). They stay valid in the v1 schema, so older reports and the committed v1 fixture still validate.
- The inventory is printed in the text summary and the Markdown report only (neither is a versioned contract, architecture §4), the way `Report.NoRoutesIn` is kept out of JSON (`json:"-"`).
- If a later step needs the inventory, a canary outcome or any other new value in JSON, that is **report v2**: `docs/schemas/report-v2.json`, a committed v2 contract fixture next to v1, and its own ADR. #265 does not need it.

### Migration

At most three in flight, from different packages (ADR 0006). Today's behaviour is unchanged until step D.

| Step | What | Behaviour change |
|---|---|---|
| ADR | This ADR (docs only; auditor only) | None |
| A | The language-neutral parts of #255: `report/bydesign.go` and goldens; Go and PHP marks vouch for nothing; marks in exact case; the deduplicated by-design rule in `cli`. Closes #213 | By-design rules only |
| B | `internal/discover`: schema, per-tier prompts with a token-budget test, validation, canary, tripwire table, inventory, replay fixtures synthesized from `expected.json` for unit tests only. Not wired into the scan | None |
| C | Move the language-neutral files of `internal/static` (`finalpath.go`, `scanners.go`, `ignore.go`, `vendorproof.go`) to a neutral package; update the layers table | None |
| D | Wire inventory, discovery and the tripwire into `creep scan` and `creep estimate`, unioned with today's static graph; amend ADR 0009's text | Files of other languages are read (no more `unsupported_language`); a Python or JS/TS file must complete both static and discovery; discovery egress starts (D1) |
| E | After #204 and #35, pass the removal gate (D4) on recorded fixtures, switch the default, delete the Flask, FastAPI and Express code, the route goldens and the route tests; rebuild `TestInputCarriesNoText` and the protections on the new path | `syntax_error` and `no_routes` stop; a repository with no candidate, read in full with every canary found, exits 0 with its readable classes covered |
| F | Drop wazero and the grammars: `dependencies.txt`, the budget net-reach exception for `internal/static`, ADR 0008 marked superseded | `go.mod` has one direct dependency (yaml/v3) |

### Removal gate (D4)

The static code is deleted (step E) only when both hold:

- discovery plus the tripwire find **100%** of the routes and sinks in every `testdata/apps/*/expected.json`, on replay fixtures with no network. These fixtures must be **recorded from a real model run** (`creep scan --record` against a configured model, with the model, endpoint kind and tier named next to the fixture), committed, and only then scored against `expected.json`. Fixtures synthesized from `expected.json` (step B) prove the plumbing (validation, union, mapping) and are allowed in unit tests only: scoring them against the file they were built from would be circular;
- the tripwire alone, which is deterministic, hits every expected sink line;
- the protection suite (`make protections`, architecture §9) is rebuilt without `internal/static` and every protection still has a broken fixture that proves it fails.

Until the gate passes, the static graph stays in the union, so recall can only grow.

This makes **#204** (reader quality with a real small model) and **#35** (the public benchmark, v0.3) prerequisites of step E: the recorded fixtures and the way they are scored come from that work, so static is not deleted before it lands.

## Consequences

- A Go, PHP, Java or Ruby repository is evaluated instead of exiting 4. New languages and frameworks need no Go code; the inventory and tripwire tables are reviewed data.
- After step F, about 3,000 lines of Go, the route goldens, 4.2 MB of grammars, the grammar build and wazero (with `golang.org/x/sys`) are gone; the binary shrinks and the budget net-reach exception goes away.
- `internal/discover` is a new layer-4 package (models, gateway, redact, state, config), next to `reader`. `planner` never imports it; `internal/cli` maps its output to `planner.Input` by explicit switch, as it maps static today.
- **Worst-case flags change ranking and tier S.** After step E every candidate has `DynamicArg` set and none is `Parameterized`, `Authenticated` or `Indirect`, so every candidate ranks at the highest risk. Tier S loses its literal-argument filter (it plans no sink with a literal argument today, and now none has one), ranking reduces to sink severity and ID (write methods are always set, so they no longer separate candidates), and more runs end at the tier's step cap (`step_cap`, exit 4), above all at tier S (32 steps). `Indirect` never lowers rank either, so helper-held sinks rank with direct ones. This is the price of D2; a smaller model sees more incomplete runs, never false clean ones.
- New fitness functions, added to architecture §9 with the code: model output never lowers a candidate's risk or removes a candidate; a missed canary makes the run incomplete; the discovery reply schema refuses free text; planner input holds no text on the new path; a planted or unsigned discovery cache entry is never served; `--record`/`--replay` reproduce a discovery run with no network; tripwire table limits hold, with a benchmark.

**Accepted residuals**

- **Targeted injection** (D2, R19). Injected text in any one file can steer the model for **every file in the same batch**, hiding entry points or sinks in all of them while it still reports the canary. creep does not split batches by trust (one file per batch would multiply canary and prompt overhead, and creep cannot tell a hostile file from a clean one before the model reads it); this scope is accepted. The tripwire still raises every signature it knows, the worst-case flags keep the rest at full risk, and sandbox verification (v0.2) checks what is found. A route with no tripwire signature that the model hides is missed, and the run can still exit 0.
- **Whole-file egress** (D1, R20). More of the repository leaves the machine than with slices: every inventoried source file, redacted. Consent, the allowlist, the budget and `egress.log` are unchanged, and a consent stored before step D carries over to it with no new prompt ([Consent](#consent-for-whole-file-egress-d1)); `creep estimate` shows the volume first; the docs recommend a local model for sensitive code.
- **Nondeterministic live gate.** Two live runs on the same commit can propose different candidates, so a live CI gate can differ between runs. Replay is deterministic, the cache makes repeated runs stable while it is valid, and the union keeps the tripwire and (until E) static as a floor.
- **Quality may drop until measured.** Precision and recall with a real small model are not measured yet (#204, benchmark #35 in v0.3). The removal gate covers only the testdata apps; until #35, findings on other languages carry the same `probable` status and calibration tier as today, and the README says that quality on other languages is not measured.
- Calibration stays Python and JS (D5), so the per-class tier is measured on those languages, not on the scanned one.

## Amendments (2026-11-19)

Recorded from the #268 audit (step B) and the maintainer's ruling on the removal gate, and applied in #265 steps C–F (one PR). Each one narrows or makes concrete a rule above; none loosens D1–D5.

1. **NUL bytes and unreadable files.** A source file whose bytes hold a NUL, and an extensionless file that cannot be read (so its bytes cannot say whether it is source), are listed `read_failed`, never dropped.
2. **A manifest name wins over the extension.** The inventory classifies a file named as a manifest (such as `package.json` or `go.mod`) by that name before it looks at the extension.
3. **Sink kinds.** eval and deserialization sinks map to the existing `shell` kind for now, so they are planned at full risk. `prototype_pollution` needs a new sink kind and planner class; that is out of #265's scope.
4. **Bounds failures are not retried.** A reply that cites a file, line or entry outside the batch is invalid for the whole batch (`parse_failed`), with no retry: a retry costs a call and would let a model probe the bounds.
5. **Canary seed.** The seed is 32 bytes from `crypto/rand`, made once per recording and kept only in signed run state (`.creep/cache`, the per-user state secret, the #160 rule): a live run reuses it so its discovery requests can be served from the cache, `--record` makes a new one, and `--replay` uses the recorded one; with none (or a planted one) replay uses an unstored seed, so every discovery request misses and the run ends `send_failed` with no model call. `creep estimate` reads the stored seed and never writes one. The seed never leaves the machine; the token and position derived from it do.
6. **The canary template is public.** It is in the repository (`internal/discover/canary.txt`), so an attacker can write an injection that names its shape. This widens R19: the canary proves the model followed the instructions for a batch, not that no file in the batch steered it. The random names and position still stop a reply written in advance.
7. **Batch and prompt budgets.** A discovery call's user turn is at most 8 KiB at tier S, 32 KiB at M and 128 KiB at L, with at most 8 files per batch; the system prompt plus schema is at most 2,900, 3,800 and 4,700 bytes (S, M, L), checked by `prompts_test.go`. The canary takes part of each batch, so at tier S a file over about 7.5 KiB fits no call and is listed `too_large`; at M and L the limit is about 31.5 and 127.5 KiB.
8. **Which route a sink belongs to.** A sink takes, in order: the entry the model linked it to; else the innermost proposed entry whose span holds its line; else a file-level route for its file. When more than one link exists, the first model link wins. A file-level route has no entry span, so the reader's slice starts at the sink line and walks back, never at line 1 of the file.
9. **Amended removal gate (D4), maintainer ruling 2026-11-19.** The static code is deleted when the tripwire alone, which is deterministic and needs no model, finds **100% of the sinks that have a planner kind** in every `testdata/apps/*/expected.json` (`TestTripwireRecall`, in `make protections`), and the protection suite is rebuilt without `internal/static` with a broken fixture for each protection. Recall of routes and entry points, and recall measured on fixtures recorded from a real model, move to #204 and #35; they no longer block steps E and F. #265 steps C–F therefore land in one PR, with no period in which discovery is unioned with the static graph.

Implementation notes for steps C–F:

- **Step C.** The neutral package is `internal/repofile` (layer 1, no internal imports): final-path refusal, optional-scanner lookup, the vendor, generated and minified marks, vendor evidence, and the line escaping the reader and discovery share. `cli/vendorproof.go` and `cli/trackedtree.go` stay in `cli`, because they use `gitindex` and the scan's `os.Root`.
- **Marks are believed only for files with nothing in them.** A vendor path that no installed tree proves, a generator header or a minified shape lists a file by design only when discovery read it in full and found no candidate (no sink and no proposed entry). A file with a candidate is evaluated whatever its mark (#213).
- **The discovery cache in the user cache directory ([Cache](#cache)) is deferred.** `--record`/`--replay` and the default live run already record and serve discovery calls through the signed run-state cache in `.creep/cache`, so repeated runs on the same tree are stable; the between-repository cache is a follow-up.
- **Symlinked directories** (#214 I5): the walk never follows a directory link. Superseded by the ADR 0009 amendment for #214: a link whose target does not name, over walked names, an entry the walk reached (absolute, outside, missing, into the root's `.git` or `.creep`, or a Windows junction) is listed `not_regular` (exit 4), or `vendor` in an installed tree; a relative link to a directory the walk covers (pnpm and workspaces on Unix) is still not listed.
- **Scan deadline (#260).** Discovery runs under `budget.max_seconds` like the reader: past the deadline it reads no file and makes no call, and every file left (unread, or in a batch the deadline cut or never sent) is listed `budget`; the file whose redaction the deadline cut is `redact_failed`.
- **Estimate.** `creep estimate` runs discovery against its meter with an empty reply and counts a batch whose only fault is the missed canary as read in full; its candidate count is the tripwire's, a floor.
- No Go fixture was added to `testdata/apps`: `internal/tools/testapps` admits Python and JavaScript apps only, and widening that guard is its own change. The Go, PHP, Java and Ruby protection (`TestScanEvaluatesAnyLanguage`) builds its repositories in `t.TempDir()`.
- **Files over 1 MiB and the extension list (#270 review).** A file over `redact.MaxFileBytes` is opened for its first 8 KiB only (`discover.HeadBytes`): source by name or shebang is listed `too_large`, anything else is not source, so a large binary or data file no longer makes every run incomplete. The inventory gained the common server-side template and include extensions (PHP, Java with JSP tags and JSF, Ruby, .NET, classic ASP, Node, Python, Elixir, Perl CGI and PSGI, ColdFusion) and a `template` language for templates whose host varies. Files with any other extension are not read and not listed; the README lists both sides, and `TestDocsListInventory` and `TestDocsListShebangs` keep its lists equal to the table.

## Amendment (#366): language-neutral file rules

- **Status:** Accepted (maintainer, 2026-11-27)
- **Date:** 2026-11-27

The maintainer's rule (#358): creep must need no per-language or per-ecosystem data or code to work on a language. Three rules above broke it: the inventory decided what is read (an unlisted extension was not read, and the run could still exit 0), vendor trees were known only by `node_modules` and `venv` marks, and the generated and minified marks knew only some languages' comment syntax and bundles. Decided:

1. **Every text file is read.** A regular file is opened unless `internal/discover/formats.txt` names it as a text format (prose, data, lockfiles, vector images), which is never opened and is listed `not_code`. A file whose name is a binary format of that list (images, fonts, media, archives, objects, documents, data stores) is listed `binary` when its first 8 KiB hold a NUL or are not UTF-8; any other file only when that head holds a NUL and is not UTF-8, since text with a NUL is `read_failed`, labeled or not (#268; tester follow-up). `.json` is config: read like any text file, and listed `not_code` only when it does not fit one discovery call. Any other file is text, read whole and sent to discovery. The list names formats only, never a language (`TestFormatsNameNoLanguage`), and the README lists it (`TestDocsListFormats`). A text file that cannot be read in full is a gap (`read_failed`, `too_large`, ...), so exit 0 never hides one (`TestExitZeroNeverHidesUnreadText`, in `make protections`).
2. **The inventory only labels.** Its rows are a prompt hint ("FILE n (language, ...)") and report counts; a file no row names is labeled `text`. The one read a label still changes is fail-closed: a file labeled as a language that holds a NUL is `read_failed`, not `binary` (amendment 1 above, #268), as is a file starting with a UTF-16 byte order mark. Manifests are read unless a lockfile pattern names them: `Dockerfile`, `requirements.txt` and `package.json` (JSON is config) are read, `package-lock.json` and `yarn.lock` are not.
3. **Vendor is what the repository ignores and git does not track.** A file is `vendor`, not read, only when the repository's own `.gitignore` files (git's precedence: nearest directory first, then `.git/info/exclude`) ignore it or a directory above it, and the git index tracks nothing in the topmost ignored tree, compared by file identity as before (#213). Committed code is always read, whatever its directory is called; an untracked file the patterns do not ignore is the author's work and is read; with no readable index nothing is vendor. Global excludes are host data and are not read. The matcher (`repofile.GitIgnore`) is bounded: 256 KiB per ignore file and a dynamic-programming match, so a hostile pattern costs patterns times path depth.
4. **Generated and minified marks read bytes only.** Generated: one of the first five lines (first 1 KiB) holds `@generated` as a word, or `generated` with `do not edit` or `do not modify`, in any case and comment syntax. Minified: nine tenths of the bytes on lines over 500 bytes, in any file. Both still label only a file read in full with no candidate, so a loose match can never hide code. No vendor or generated rule names a package manager, dependency directory or language (`TestRulesNameNoEcosystem`).
5. **Recall rests on model discovery.** The tripwire stays a best-effort hint that only adds candidates; a language with no tripwire row is found by the model alone, and the README says so.
6. **Report v1 gains `not_code` and `binary`**, both left out by design (they count in the by-design summary and do not block `--baseline-write`), additively, as the #26 amendment allows.

Cost, measured on the committed trees: over every `testdata/apps` variant the bytes discovery reads grow from 16,535 to 23,623 (about 4,100 to 5,900 tokens at 4 bytes a token, +43%): the `Dockerfile`, `compose.yaml` and `requirements.txt` of each app; the wheels in `flaskpg` are binary. The bench corpus sends one named source file per case, so its requests do not change. `creep estimate` runs the same discovery against its meter, so it reflects the wider read with no change of its own (`TestEstimateCountsAnyTextFile`). Consequence: a text file that fits no discovery call (about 7.5 KiB at tier S) now makes a run incomplete where it was not read before; a large data file in a listed format does not.
