# ADR 0009: `creep scan` and `creep why` contract, report v1 additions

- **Status:** Accepted (maintainer approval on #205)
- **Date:** 2026-11-16
- **Deciders:** @Ludocius
- **Changes:** the CLI contract (`scan`, `why`), the JSON report schema v1 (architecture §4), report file locations

## Context

#175 wires the pipeline (calibrate → static → planner → reader → report) into `creep scan` and builds `creep why <id>`. Both were stubs that exited 2. Wiring them fixes public behavior that nothing has decided yet:

- Where `scan` reads the repository from and where it writes reports, so `why` can find them.
- What `why` prints. The JSON report v1 has no evidence, no reason for a not-evaluated finding and no flag for a verdict from a cut slice (the #200 audit: a `not_vulnerable` from a partial slice must never read as clean).
- Which files and sinks make a run incomplete (exit 4, ADR 0007). Static analysis, the planner and the reader each leave things out, some by design (vendor code, tier S's low-risk skip) and some because they could not do better (syntax errors, caps, step and token bounds, model failures).
- How the gate (`gates.pr`, `<status>:<severity>`) is evaluated when findings carry a class but no severity.

No version has been released, so no consumer depends on report v1 yet.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Bump the report to v2 for the new fields | Follows the schema rule literally | A second schema and fixture before any release; v1 would never ship |
| B. Amend v1 additively before the first release, keep the rule from the first release on | One schema at v0.1; every new field is optional, so the committed v1 fixture still validates | v1 changes once more after #166 |
| C. Keep the report as it is and give `why` its own evidence file | No schema change | A second file format to keep in step; `why` and the report could disagree |

## Decision

Option B, and the CLI contract below. What decided it: nothing has been released, and one file (the JSON report) staying the single source for `why` is simpler than two formats.

**`creep scan [.]`** scans the current directory (the project config `creep.yaml` and `.creep/` are read from it, as `resume` does). Any other path argument exits 2. It needs `model.contract` (`openai` or `anthropic`; the command contract is #6), `model.endpoint` and `model.name`, or it exits 2 before touching the disk. The tier comes from calibration (`calibrate.RunCached`, fixed seed 1, cached in the user cache directory for `calibration.cache_days`). Reports go to `.creep/report.json`, `.creep/report.md` and `.creep/report.sarif`, per `report.formats`; each is removed and created anew inside `.creep`, never written through a planted link. Every `.creep/report.*` left from an earlier run, or planted in the repository, is removed when the run opens its state and before any model call, so a stopped run never leaves a report that reads as this run's; a name that cannot be removed exits 2. `.creep` gets a `.gitignore` of `*` on first use. `--format text` prints a summary; `json`, `sarif` and `markdown` print that report to stdout, and the incomplete mark also goes to stderr. `--record` and `--replay` use the run-state cache (#8) in `.creep/cache`.

**Exit codes** follow ADR 0007. Before a report exists: 2 for usage, configuration, consent and local errors; 3 for a failed calibration call. After it: `exitcode.ForReport`. The run is **incomplete** (exit 4) when anything that could hold a finding was not evaluated in full:

- an early stop: `run_full`, `budget`, `send_failed`, or `planner_rejected` (`planner.ErrInput`; then every class is not evaluated);
- a sink the planner skipped for `step_cap` or `budget` (the decoy-flooding mitigation from the #199 audit), a sink of a kind the planner cannot take yet (`unmapped_kind`; Express's `nosql` sinks were one until #212 mapped them), or a hypothesis the reader could not answer (`file_not_scanned`, `line_out_of_range`, `lines_shifted`, `run_full`, `invalid_output`, `inconclusive`, an unmapped kind or class);
- a verdict from a partial slice (`partial_slice`);
- a file not evaluated in full: `read_failed`, `too_large`, `not_regular`, `invalid_path` (a name static refuses, such as `a:b.py`), `parse_failed`, `syntax_error`, `truncated`, `unsupported_language` (every file whose extension is in the closed list of source languages with no grammar in `internal/cli/sourceext.go`: Go, PHP, Java, Kotlin, Scala, Ruby, C#, Rust, Elixir, C/C++ and others), and the gateway and reader reasons. Files with any other extension (markup, config, data, shell) are not source and are not listed.

Vendor, generated and minified files (a source file of any listed language under a vendor directory is `vendor`) and tier S's `low_risk` skips are left out by design: they are listed, but do not make the run incomplete. The run's reason is the first of these in that order.

**Report v1 additions** (all optional): a finding's `reason` (an ID), `partial`, `confidence` (0-100) and `evidence` (`{start, end}` line ranges); the not-evaluated file reasons `lines_shifted`, `vendor`, `generated`, `minified`, `not_regular`, `invalid_path`, `parse_failed`, `syntax_error`, `truncated` and `unsupported_language`. Finding IDs are `sink-<n>`, the static sink ID. Report classes use the calibration names (`sqli`, not the reader's `sql_injection`), plus `template_injection`; `nosql_injection` is evaluated since #212; classes the pipeline cannot evaluate yet (`idor`, `missing_auth`, `prototype_pollution`) are listed as not evaluated.

**Gate**: a probable or verified finding trips `gates.pr` by its class's severity: `sqli`, `nosql_injection` and `command_injection` critical; `path_traversal`, `ssrf` and `template_injection` high; any other class critical.

**`creep why <id>`** checks the ID against the report's ID pattern, reads `.creep/report.json` (without creating `.creep`, without blocking on a FIFO, at most 64 MiB) through `report.ReadJSON`, which refuses unknown fields and invalid findings, and prints status, class, escaped location, reason, confidence, evidence lines and the partial flag. A missing report, malformed or unknown ID exits 2.

## Consequences

- `internal/cli` holds the static→planner and planner→reader mappings as explicit switches; `plannermap_test.go` fails when either side gains a value. A static kind with no planner support yet is named in `pendingKinds` with its issue (empty since #212 mapped `static.SinkNoSQL` to `planner.SinkNoSQL` and `nosql_injection`); its sinks are listed as not evaluated (`unmapped_kind`) and never planned. The scan extracts Python with Flask and FastAPI and JavaScript, TypeScript and TSX with Express (#87).
- `reader.Signal` gains `Partial`; `reader.CallTokens` gives the planner its per-step cost.
- From the first release on, report fields change only with a `schema_version` bump, as the schema says.
- `resume` still fails closed; continuing a run needs per-step resume, a follow-up.
- `--diff`, a `--gate` choice (`gates.nightly`) and a severity per finding are not decided here.

## Follow-up: what counts as left out by design (v0.1 release pentest P4, #213)

The repository's author decides where files sit, what their first comment says and what they are named, so "by design" above let first-party code be skipped while the run read complete. Since the v0.1 release pentest, a skip needs evidence, and anything without it is read like first-party code:

- A file under a vendor-named directory is listed as `vendor` without being read only when its package manager's mark is a regular file in the repository, for that mark's language, with exact case (`static.VendorEvidence`): `node_modules/<pkg>/package.json` (or `@scope/<pkg>`) for JavaScript and TypeScript, `venv/pyvenv.cfg` or `.venv/pyvenv.cfg` for Python, `vendor/modules.txt` for Go, `composer.json` next to `vendor/` for PHP. Other names (`third_party/`, `site-packages/`, `VENDOR/`, a Python file under `node_modules/`) have no evidence.
- Every other file is read and parsed. A vendor path, a generator header or the minified shape (now nine tenths of the file's bytes on lines over 500 bytes, so one padding line is not enough; a `.min.js` name never counts) is believed only for a file that parsed without errors and holds no route. Such a file is listed with its reason and stays by design; a file with a route is extracted and evaluated like any other.
- A Go, PHP or other ungrammared file under `vendor/` without the mark is listed as `unsupported_language` and makes the run incomplete.

The report reasons and schema do not change, and every left-out file is still listed (#88). Residual: the evidence files are themselves in the repository, so an author can plant a `pyvenv.cfg` or `package.json` next to code that its language never imports from there; the file is still listed, and the planted marker shows in the pull request diff. The by-design count next to "covered" that #213 still asked for is the amendment at the end.

## Amendment: a run with no route is incomplete (#207)

Before #207, a repository where static extracted no route (and so no sink, since every sink belongs to a route) read as complete with every readable class `covered` and exited 0: a Django-only `views.py` with string-built SQL, Python or JavaScript without Flask, FastAPI or Express routes, or an empty repository. Every file was parsed, so nothing was listed, yet nothing was evaluated for any class.

| Option | Pros | Cons |
|---|---|---|
| A. Each class `not_evaluated`, run incomplete with reason `no_routes` (exit 4) | Reuses the incompleteness rules and exit code 4 (ADR 0007); the class status says exactly what happened; no schema or exit-code change | A repository with no web code at all (a library, a CLI tool) never exits 0 |
| B. Each readable class `partial` with a closed reason | Keeps `not_evaluated` for classes the pipeline cannot read | `partial` claims some evaluation took place; a class row has no reason field, so it needs a schema change |
| C. A new exit code | Separates "nothing to scan" from "scan cut short" | Changes the exit-code meaning (a new ADR); CI gates already treat 4 as not clean |

**Decision:** option A. When static extracts no route from the analysed files (or there is no analysable file), the scan neither plans nor calls the reader; every class is `not_evaluated`, and the run is incomplete with reason `no_routes`. The reason comes after the early stops, finding gaps and file gaps above (a Go-only repository still reads `unsupported_language`, with every class not evaluated), and before a failed scanner. The text summary prints `routes: no Flask/FastAPI/Express routes found; no class was evaluated` and the Markdown report a bold line with the same names, both from `static.FrameworkNames`, so a framework added to static is named without touching the CLI or the report. The JSON report states it through `run.reason`; the framework names are not a report field (`Report.NoRoutesIn` is `json:"-"`), so report v1 does not change. No line counts what such a run left out, since it evaluated nothing (#248): the incomplete mark reads `static found no route, so no class was evaluated` in place of a file count, the findings line says `no sink to evaluate` in place of `0 not evaluated`, and the Markdown Not evaluated section says static analysis found no route in place of `Every file was evaluated`, still listing any file left out. The scan makes no planner or reader call, but the tool canary and, on a cold cache, calibration still reach the model before static runs. A repository with at least one route is unchanged: a Flask route without sinks, or a Flask app whose sinks are all discarded, exits 0 with its classes covered.

Residual: routes of a framework static does not recognise next to one it does (Django views beside one Flask route) are still not flagged; new frameworks land with the language kits (ADR 0012, #217).

## Amendment: a clean run names what it left out by design (#213)

The follow-up above already meets most of #213: a vendor directory is believed unread only with its package manager's mark, in exact case (`VENDOR/`, `Node_Modules/`, `app/vendor/` without the mark, `third_party/` and `site-packages/` are read); a generator header, the minified shape or a vendor name without the mark is believed only for a file that parsed cleanly and holds no route; an ungrammared file under an unproven vendor name (`src/vendor/x.go`, `third_party/svc/main.go`) is `unsupported_language`. A mark is a regular file found by `Lstat`, so a linked `package.json` or `pyvenv.cfg` proves nothing, a linked source file in a proven tree is `not_regular`, and a linked directory is not walked, so its target is read at its own path. The mark sits inside the dependency directory, which is stronger evidence than the sibling manifest #213 proposed, so that rule is not added. What was left: a run with by-design files still read `covered` for every readable class with nothing beside it.

| Option | Pros | Cons |
|---|---|---|
| A. Keep the class statuses; print the by-design count beside the coverage in the text summary, Markdown and SARIF | No schema or exit-code change; a real dependency tree stays exit 0; every clean result names what it left out | The JSON class row still reads `covered` (the files and reasons are in `coverage.not_evaluated`) |
| B. Each readable class `partial` with a closed reason when any by-design file exists | The JSON class row says it too | A class row has no reason field (schema change); every repository with an installed `node_modules` or `venv` reads partial forever, so `partial` stops meaning anything |
| C. By-design files make the run incomplete (exit 4) | Strictest | Breaks the by-design rule itself: no JavaScript or Python project with installed dependencies could pass a gate |

**Decision:** option A. `report.ByDesignSummary` counts the listed files whose reason is by design (`report.SkipReason.ByDesign`: `vendor`, `generated`, `minified`), in that fixed order, as only counts and reason IDs, never a path. The text summary prints `coverage excludes N files left out by design (vendor a, generated b, minified c), listed above` under the coverage line; the Markdown report prints a bold `No class covers the N files left out by design (…)` under the class table; SARIF adds a `creep/by-design` note to the invocation's notifications. Nothing is printed when no file was left out by design. The CLI uses the same `ByDesign` method to decide incompleteness, so the count and the rule cannot drift. The JSON report and its schema do not change.

Residual: the marks are still repository files an author can plant (listed, visible in the diff). A sink outside any route is not a static sink in any file, so a route-free generated helper called from a first-party route is no weaker than a first-party helper in another file; following calls across files is a static limit for every file (`internal/static/doc.go`).
