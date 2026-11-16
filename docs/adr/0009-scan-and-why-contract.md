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

**`creep scan [.]`** scans the current directory (the project config `creep.yaml` and `.creep/` are read from it, as `resume` does). Any other path argument exits 2. It needs `model.contract` (`openai` or `anthropic`; the command contract is #6), `model.endpoint` and `model.name`, or it exits 2 before touching the disk. The tier comes from calibration (`calibrate.RunCached`, fixed seed 1, cached in the user cache directory for `calibration.cache_days`). Reports go to `.creep/report.json`, `.creep/report.md` and `.creep/report.sarif`, per `report.formats`; each is removed and created anew inside `.creep`, never written through a planted link. `--format text` prints a summary; `json`, `sarif` and `markdown` print that report to stdout, and the incomplete mark also goes to stderr. `--record` and `--replay` use the run-state cache (#8) in `.creep/cache`.

**Exit codes** follow ADR 0007. Before a report exists: 2 for usage, configuration, consent and local errors; 3 for a failed calibration call. After it: `exitcode.ForReport`. The run is **incomplete** (exit 4) when anything that could hold a finding was not evaluated in full:

- an early stop: `run_full`, `budget`, `send_failed`, or `planner_rejected` (`planner.ErrInput`; then every class is not evaluated);
- a sink the planner skipped for `step_cap` or `budget` (the decoy-flooding mitigation from the #199 audit), a sink of a kind the planner cannot take yet (`unmapped_kind`: Express's `nosql` sinks until #212), or a hypothesis the reader could not answer (`file_not_scanned`, `line_out_of_range`, `lines_shifted`, `run_full`, `invalid_output`, `inconclusive`, an unmapped kind or class);
- a verdict from a partial slice (`partial_slice`);
- a file not evaluated in full: `read_failed`, `too_large`, `not_regular`, `invalid_path` (a name static refuses, such as `a:b.py`), `parse_failed`, `syntax_error`, `truncated`, `unsupported_language` (every file whose extension is in the closed list of source languages with no grammar in `internal/cli/sourceext.go`: Go, PHP, Java, Kotlin, Scala, Ruby, C#, Rust, Elixir, C/C++ and others), and the gateway and reader reasons. Files with any other extension (markup, config, data, shell) are not source and are not listed.

Vendor, generated and minified files (a source file of any listed language under a vendor directory is `vendor`) and tier S's `low_risk` skips are left out by design: they are listed, but do not make the run incomplete. The run's reason is the first of these in that order.

**Report v1 additions** (all optional): a finding's `reason` (an ID), `partial`, `confidence` (0-100) and `evidence` (`{start, end}` line ranges); the not-evaluated file reasons `lines_shifted`, `vendor`, `generated`, `minified`, `not_regular`, `invalid_path`, `parse_failed`, `syntax_error`, `truncated` and `unsupported_language`. Finding IDs are `sink-<n>`, the static sink ID. Report classes use the calibration names (`sqli`, not the reader's `sql_injection`), plus `template_injection`; classes the pipeline cannot evaluate yet (`nosql_injection`, `idor`, `missing_auth`, `prototype_pollution`) are listed as not evaluated.

**Gate**: a probable or verified finding trips `gates.pr` by its class's severity: `sqli` and `command_injection` critical; `path_traversal`, `ssrf` and `template_injection` high; any other class critical.

**`creep why <id>`** checks the ID against the report's ID pattern, reads `.creep/report.json` (without creating `.creep`, without blocking on a FIFO, at most 64 MiB) through `report.ReadJSON`, which refuses unknown fields and invalid findings, and prints status, class, escaped location, reason, confidence, evidence lines and the partial flag. A missing report, malformed or unknown ID exits 2.

## Consequences

- `internal/cli` holds the static→planner and planner→reader mappings as explicit switches; `plannermap_test.go` fails when either side gains a value. A static kind with no planner support yet is named in `pendingKinds` with its issue (`static.SinkNoSQL`, #212); its sinks are listed as not evaluated (`unmapped_kind`) and never planned. The scan extracts Python with Flask and FastAPI and JavaScript, TypeScript and TSX with Express (#87).
- `reader.Signal` gains `Partial`; `reader.CallTokens` gives the planner its per-step cost.
- From the first release on, report fields change only with a `schema_version` bump, as the schema says.
- `resume` still fails closed; continuing a run needs per-step resume, a follow-up.
- `--diff`, a `--gate` choice (`gates.nightly`) and a severity per finding are not decided here.
