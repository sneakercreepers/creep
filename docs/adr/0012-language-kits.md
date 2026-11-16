# ADR 0012: Language kits as data

- **Status:** Accepted (maintainer approval on #220, 2026-11-16)
- **Date:** 2026-11-16
- **Deciders:** @Ludocius
- **Changes:** `internal/static` internals (engine plus kits), the language-kit contract (architecture §4, §5), a new `creep kit test` command

## Context

Issue #217. Each framework in `internal/static` is hand-written Go today. `py*.go` (Flask, FastAPI) and `js*.go` (Express) add up to about 2,800 lines of non-test code: AST walks, receiver and mount resolution, auth detection and two sink tables (`pySinkSpecs`, `jsSinkSpecs`). Every new language would add another package's worth of Go and needs both Go and AST skills from contributors. Architecture §5 already lists language kits as an extension point ("data, not code"), and §4 lists them as a contract with their own `version:`. Nothing defines the format yet.

The parser is already data. Grammars are pinned WebAssembly modules (ADR 0008). Each parse runs in a **fresh instance** and returns flat records that the host validates (`decodeTree`) before it builds a `Tree`. Whatever we choose must keep that boundary, invariant 3 (the `Graph` holds only IDs, enums, booleans and counts), the fail-closed rules (`DynamicArg`, `Partial`, `File.Truncated`, ADR 0009) and the per-file caps.

### Spike: can kits use tree-sitter queries?

The question was whether the embedded grammars expose tree-sitter's query API (`ts_query_new`, `ts_query_cursor_exec`, captures) to Go. Measured on 2026-11-16 (Windows laptop, Go 1.27.4, wazero v1.12.0, one run each). The spike ran in a scratch directory and is not committed.

- **The shipped modules do not expose it.** `python.wasm` and `javascript.wasm` each export 8 functions: `_initialize`, `creep_alloc`, `creep_parse`, `creep_records`, `creep_symbol_count`, `creep_symbol_name`, `creep_field_count` and `creep_field_name`. None of them is a query function. `build.sh` links the whole runtime (`lib.c`), but `--strip-all` and the linker's dead-code removal drop everything `glue.c` does not export.
- **Adding the exports works, but it is costly.** `glue.c` was extended with `creep_query_new` and `creep_parse_query` (parse, walk, then a query cursor with a match limit, five words per capture) and rebuilt with the pinned `build.sh` toolchain in `golang:1.27.4`. Results for a five-pattern Flask query (route decorators, method calls, plain calls, `from` imports, constructor assignments). The input was `testdata/apps/flask/vulnerable/app.py`, repeated to reach each size:

| Input | Nodes | Parse + decode today | Guest parse + query | of which `ts_query_new` | Go-side matcher over the decoded tree |
|---|---|---|---|---|---|
| 1.7 KB | 611 | 2.0 ms | 26.9 ms | 24.9 ms | < 1 ms |
| 64 KB | 23,791 | 59 ms | 97 ms | 28.6 ms | < 1 ms |
| 256 KB | 95,161 | 214 ms | 308 ms | 24.0 ms | 4.5 ms |
| 1 MiB | 380,641 | 923 ms | 1,472 ms | 25.2 ms | 26.6 ms |

  - Each file gets a fresh instance (ADR 0008), so the query must be compiled again for every file: about 25 ms for five patterns. On a typical repository of small files, that is 10 to 13 times the cost of the parse itself.
  - Running the query in the guest adds about 50% to large files.
  - Each module grows: `python.wasm` from 565,327 to 629,807 bytes (+11%), `javascript.wasm` from 535,939 to 596,225 bytes. Every grammar hash changes, and the record ABI grows a second record type that the host must validate.
  - The Go-side matcher in the table is a minimal structural matcher (node types, fields, nested children) over the records we already decode. It costs about 3% of the parse at 1 MiB.

  **To reproduce:**

  1. Copy `internal/static/grammars/` to a scratch directory outside the repository.
  2. Append four exports to `glue.c` (call the result `glue_q.c`):
     - `creep_query_new(src, len)` calls `ts_query_new(CREEP_LANGUAGE(), ...)` and keeps the query in a static variable.
     - `creep_parse_query(src, len, max_nodes, max_caps)` does what `creep_parse` does, then runs `ts_query_cursor_new`, `ts_query_cursor_set_match_limit(256)` and `ts_query_cursor_exec` on the same root. It appends `{match id, pattern, capture, start byte, end byte}` for each capture of each `ts_query_cursor_next_match`.
     - `creep_captures` and `creep_capture_count` return the captures and their count.
  3. Point `build.sh` at `glue_q.c` and run it as its header says, in `golang:1.27.4`.
  4. Write a Go program (wazero v1.12.0, the runtime config from `parser.go`) that:
     - lists `CompiledModule.ExportedFunctions()` of the shipped and the rebuilt modules;
     - repeats `testdata/apps/flask/vulnerable/app.py` up to 64 KiB, 256 KiB and 1 MiB;
     - for each size, times a fresh instance with `creep_parse` plus decoding against a fresh instance with `creep_query_new` plus `creep_parse_query`;
     - times a recursive matcher (node symbol, field ID, every child pattern matching some child) over the decoded records.
  5. Use these five patterns:
     - `decorated_definition` with a `decorator` whose `call` has an `attribute` function and a first `string` argument, and a `function_definition` name;
     - a `call` with an `attribute` function;
     - a `call` with an `identifier` function;
     - `import_from_statement`;
     - an `assignment` of a `call` to an `identifier`.

  The engine PR adds a committed benchmark of the Go matcher (`BenchmarkKitMatch`) next to `BenchmarkParseMaxFile`. The guest-query build is not kept, because option B is not chosen.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. One Go package per language (today) | Precise; no new format | Cost grows linearly with each language; contributors need Go and AST expertise; the design rates it "Costly" |
| B. Kits whose `.scm` queries run inside the guest (rebuilt `glue.c` with query exports) | Full tree-sitter query semantics, including quantifiers and every predicate | Spike: about 25 ms of `ts_query_new` per file because instances are fresh, +50% on large files, +11% module size, new guest ABI and new hashes; query results come back as guest data that must be validated again |
| C. Kits whose `.scm` queries run in a Go matcher over the validated `Tree` (chosen) | No grammar rebuild, no ABI change; matching runs only on validated host data; under 1 ms for typical files and about 3% of parse at 1 MiB; the subset and its limits are ours to bound | We implement and maintain a matcher for a subset of the query language; kits cannot use features outside the subset |
| D. Import SARIF from semgrep or CodeQL (#10) as the extraction engine | Wide coverage for free | Gives findings, not the route, sink and auth graph the planner needs. It stays complementary (detect-only, #10), not an engine |
| E. Model-only fallback for languages without a kit | Cheap breadth; honest partial coverage | No static graph at all. It stays complementary and is a separate follow-up |
| F. CodeQL | Mature dataflow | Licence restrictions (already rejected in the design) |
| G. Kit logic in an embedded scripting language (Starlark, Lua, JS) | Expressive | A new dependency (invariant 6); code instead of data, with its own sandbox and its own budgets; review cost close to option A |

## Decision

**Option C.** Kits are data: tree-sitter query files, a closed sink table and fixtures. A generic Go engine in `internal/static` runs a bounded subset of the tree-sitter query language over the `Tree` the host has already validated. What decided it: the spike shows that guest-side queries cost about 25 ms per file just to compile, which is more than the parse for most files, and they change the pinned grammar ABI. The Go matcher reuses the validated tree, keeps ADR 0008 unchanged and costs a few percent.

### 1. Kit format and versioning

Kits live in `internal/static/kits/<language>/<framework>/` so `go:embed` can reach them:

```
kit.yaml     format, id, version, grammar, extensions, detection, IDs, semantics
routes.scm   route declarations: receiver, verb, path, handler
mounts.scm   receiver constructors, mounts and prefixes
auth.scm     decorators, dependencies, middleware and call captures
sinks.yaml   closed table: callee pattern → SinkKind, fixed API ID, argument rules
fixtures/    vulnerable/ and safe/ sources plus graph.golden (format of testdata/routes/*.golden)
```

- `kit.yaml` has `format: 1`, the engine's schema version. The engine refuses a format it does not know, and refuses unknown keys at any level (strict decode with `go.yaml.in/yaml/v3`, already allowed by ADR 0001). `version:` is the kit's own semver; the report records `id@version` for each kit used, so a run can be reproduced.
- `grammar:` names an embedded grammar (`python`, `javascript`, `typescript`, `tsx`). **Kits cannot ship a `grammar.wasm` in v0.2.** Grammars come only from ADR 0008's embedded build (`build.sh`, `SHA256SUMS`, the import allowlist). The engine finds grammars from the embedded set listed in `SHA256SUMS`, not from a Go map. So a new grammar is a pinned artifact added through `build.sh`, not extraction code. Allowing kit-shipped grammars later needs its own ADR.
- **Stable IDs are declared in the data and never derived from it.** `kit.yaml` fixes the `Language` and `Framework` values, and every `sinks.yaml` entry has an explicit `api:` number. The embedded kits keep today's values (Python 1, JavaScript 2, TypeScript 3, TSX 4; Flask 1, FastAPI 2, Express 3; Python APIs 1–N, JavaScript APIs from 128) so goldens stay byte-identical. The registry refuses duplicate IDs and overlapping ranges. Entries are append-only, as the comment on `pySinkSpecs` already requires; `creep kit test` checks them against the kit's golden.
- `SinkKind` stays a **closed Go enum**. A kit can only reference existing kinds. A new kind needs planner, reader and report support and an explicit mapping (`plannermap_test.go`), so it is a Go change on purpose.
- How path parameters are counted is a closed enum the kit picks (`angle` for Flask, `brace` for FastAPI, `colon_star` for Express), replacing the `switch` in `pathParams`.

### 2. Query subset

Kits use tree-sitter's S-expression syntax, so the files stay readable and can be checked with the upstream CLI. The matcher supports: node patterns, `_`, field constraints, negated fields (`!field`), alternation `[...]`, the anchor `.`, and captures. Predicates are a closed set: `#eq?`, `#not-eq?` and `#any-of?`, plus `#match?` with an RE2 pattern of at most 256 bytes (linear time). Quantifiers (`*`, `+`, `?`) and any other predicate or directive are **rejected when the kit is loaded**, not ignored. A child pattern matches any child in order, which covers decorator lists and argument lists without quantifiers.

Capture names are a closed vocabulary of roles (`@route.path`, `@route.verb`, `@route.handler`, `@mount.prefix`, `@auth.middleware`, `@sink.call`, `@import.module`, ...). An unknown role fails the load.

### 3. What stays in Go

The engine owns everything that must stay uniform and audited. A kit cannot switch any of it off:

- **Mapping captures to the Graph.** Roles map to `Route`, `Sink` and `File` fields through a fixed table. Captured text goes only to `Locations` or to Go-side resolution, never into the `Graph`; the reflection guard (`TestGraphHoldsNoStrings`, as in #199) stays as it is. Invariant 3 holds no matter what a kit says.
- **Fail closed.** A required role that is missing or cannot be resolved (a non-literal path, a handler that is not in the file, a mount that cannot be resolved) sets `DynamicPath` or `Partial` and `File.Truncated`. It is never dropped silently.
- **Binding and scope resolution.** `DynamicArg` analysis, receiver scoping, import resolution and mount-chain composition depend on the language's semantics, which queries cannot express. They become **semantics modules** keyed by grammar family: `python` (today's `pybind`, `pyast`, `pymounts`) and `ecmascript` (`jsbind`, `jsscope`, `jsmounts`, `jschains`). A kit selects one with `semantics:`. A kit with `semantics: none` gets the generic conservative model: only a literal written in the sink call counts as constant, every name is dynamic, and every mount or receiver the kit cannot resolve is partial. **Under `semantics: none`, a route never has auth.** `@auth.*` captures are ignored there and `Route.Auth` stays empty, because auth comes only from the Go-side semantics module: it alone checks receiver scope, binding and source order. An auth capture that a semantics module cannot resolve claims no auth and marks the route `Partial`. A new language therefore needs no Go code. It is less precise but never unsafe; precision for a new family is an optional Go contribution later.
- Caps and budgets (`maxFileRoutes`, `constVisits`, `scanVisits`, mount depth), vendor, generated and minified rules (`IgnoreReason`), and `unsupported_language` listing. `internal/cli/sourceext.go` drops an extension from the unsupported list only when a loaded kit claims it.
- **One rule for migration:** framework behavior that queries cannot express (for example Express's source-order middleware) becomes a generic engine feature behind a closed kit option (such as `auth_order: source`), never a `switch framework` branch. If a behavior fits neither, migration stops and this ADR is revisited.

### 4. Trust model for loading

- Product scans use **embedded kits only**, compiled into the binary with `go:embed` and covered by the same review and CODEOWNERS as `internal/static`.
- `creep kit test <dir>` loads a kit from a directory named explicitly on the command line, for kit development. It never runs a scan.
- **Kits never come from the scanned repository.** A `kits/` directory, a `kit.yaml` or a lock entry inside the scan root is ignored. A kit path that resolves inside the scan root is refused. Project config (`creep.yaml`) cannot add kits; the rule from #61 applies.
- External kits during a scan (from user config or org policy, pinned `repo@sha` plus SHA-256 in `creep.lock`, read from the user cache) arrive with recipes in v0.3 and share their loader and pinning code. Until then, no such path exists, so it fails closed. Loading never uses the network; fetching is a separate, explicit command.

### 5. Limits

Checked when a kit is loaded: at most 256 patterns per kit, 64 KiB per `.scm` file, pattern nesting depth 8, 1,024 `sinks.yaml` entries and 32 roles per pattern. A kit outside these limits is refused.

Checked per file: the matcher is iterative, and its work is bounded by nodes × total pattern size, under a visit budget like `constVisits`. Matches per file are capped at 2^16. Hitting either limit marks the file `Truncated` (fail closed), never silently cuts results. Matching runs under the scan context, so cancellation and the caller's deadline apply. Benchmarks back the documented worst case: a hostile 1 MiB input (`BenchmarkParseMaxFile`) and a hostile kit at every limit.

### 6. Migration

Flask, FastAPI and Express move one at a time, each in its own PR. A kit plus its share of the generic engine replaces the framework's Go, and that Go is deleted in the same PR. The gate for each PR is that the following stay **unchanged and pass**: `TestFixturesGolden` and `testdata/routes/*.golden` byte for byte, the `expected.json` checks, the planner-text tests (`planner_text_test.go`, `jsplanner_text_test.go`) and every fail-closed test listed in architecture §9. Parse plus extract throughput must not be worse than `main` (#171 benchmarks).

### 7. `creep kit test <dir>`

The command validates the kit (format, limits, roles, ID ranges), then runs it on `fixtures/` through the same engine as `scan`. It prints a golden diff and plants text markers in every capture position to prove that none reach the planner-facing graph. Exit 0 on pass, 1 on a golden diff, 2 when the kit is invalid. In CI, the command runs over every embedded kit.

A minimal extra kit with `semantics: none` lives under test fixtures as proof that a kit needs no Go change. Because v0.2 grammars come only from the embedded build, the demo is a framework the engine does not model (for example Koa) on an embedded grammar. A Go `net/http` or PHP Slim demo needs that grammar added through `build.sh` first. The demo is **not** embedded or shipped: architecture §6 and §7 keep shipped languages to Python and JS/TS before v1.0.

### 8. Relation to recipes (v0.3)

Recipes add source, sink and hint records to an existing kit. They may append `sinks.yaml` entries in their own reserved API range, but cannot add queries or change semantics. Kits and recipes share one loader (format version, strict decode, limits, SHA-256 pinning in `creep.lock`, never from the scan root).

## Consequences

- Adding a language or framework becomes a data PR: a kit, its fixtures and a passing `creep kit test`. Contributors write queries and tables, not Go AST walks. Precision beyond the generic model still takes Go, in one semantics module per language family, not per framework.
- ADR 0008 is unchanged: no grammar rebuild, no new guest exports, same hashes. Guest-side queries (option B) stay possible later, behind instance reuse (a 0008 follow-up), if the subset proves too narrow.
- We now maintain a query-subset matcher and a kit schema. Both are closed and bounded, and the loader refuses anything outside them.
- No new dependency: YAML uses ADR 0001's parser, RE2 is `regexp`, and embedding uses `embed`.
- `docs/threat-model.md` gains kit entries with the implementation: a kit planted in the scanned repository (TB1) and a tampered embedded kit (S3).
- New fitness functions, added to architecture §9 with the implementation: a hostile kit cannot put text into the `Graph`; a kit with `semantics: none` and hostile `auth.scm` captures never sets `Route.Auth`; a planted `kits/` directory in the scan root is ignored; kit and per-file limits hold, with benchmarks; unresolved captures fail closed; every embedded kit passes `creep kit test`; kit IDs are append-only.
- The implementation follows as sub-issues of #217: engine and matcher, Flask, FastAPI, Express, `creep kit test` plus the demo kit, and docs (a "write a kit" guide, architecture §3, §5 and §9). Each goes through the full agent loop.
