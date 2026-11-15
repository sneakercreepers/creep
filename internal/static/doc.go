// Package static parses repository files into syntax trees so creep can find
// routes, sinks and auth checks without running the scanned code.
//
// It exists because the planner needs structure, not text: later passes
// (#86, #87) turn these trees into IDs and enums. Parsing uses tree-sitter
// grammars compiled to WebAssembly and run by wazero, so the binary stays
// static (CGO_ENABLED=0) and a parser bug triggered by a hostile file stays
// inside a sandbox with no file system, network, clock or environment
// (ADR 0008).
//
// Each parse gets a fresh module instance with a memory cap, a node cap and a
// deadline, and the host validates every record the guest returns before it
// builds a Tree. A Tree holds grammar node types and byte offsets only; the
// source text stays in the caller's buffer.
//
// An Extractor turns Python trees into a Graph of Flask and FastAPI routes,
// the sinks their handlers reach (SQL, shell, file, HTTP client, template)
// and how auth was seen (decorator, dependency, call). Graph holds only IDs,
// enums, booleans and counts, so it can go to the planner; paths, handler
// names and lines go to a separate Locations value for the report.
// Extraction works per file, from syntax alone: imports resolve aliases,
// blueprints and routers compose prefixes within the file, and auth is a
// name-based hint. Every walk is iterative, every per-route list and string
// is capped, and argument analysis is memoized per assignment under a
// per-file visit budget (past it, sinks count as dynamic and the route and
// file are marked partial), so a hostile file costs linear time and bounded
// memory.
//
// Known limits: a blueprint or router mounted from another file
// (register_blueprint or include_router across modules) keeps only the
// prefix and dependencies visible in its own file; add_url_rule,
// add_api_route and class-based views are not read; sinks are followed one
// helper deep within the file.
package static
