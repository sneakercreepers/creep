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
// name-based hint.
//
// DynamicArg fails closed (#185): a name counts as constant only when every
// binding of it in the function is a simple assignment of a string, number
// or tuple of them, whatever the control flow between them. Branches, try,
// tuple and starred targets, for, with, except, walrus, augmented
// assignment, parameters, imports, global, nonlocal (also from a nested
// function), match captures, nested def or class names, cycles and any
// binding not understood make it dynamic. Nested def and class headers
// (decorators, defaults, annotations, bases) are scanned as part of the
// enclosing function. A name never holds a list, since a list can change in
// place before the sink; a list literal written in the sink call can.
//
// Every walk is iterative, every per-route list and string is capped, and
// argument analysis is memoized per name under a per-file visit budget
// (past it, sinks count as dynamic and the route and file are marked
// partial), so a hostile file costs linear time and bounded memory.
//
// IgnoreReason decides, before parsing, which files are not evaluated:
// vendor directories (vendor, node_modules, site-packages, virtualenvs and
// the like, matched on directory segments of a repo-relative path; absolute
// or escaping paths are an error), files whose leading comment block
// carries an exact generator marker ("Code generated ... DO NOT EDIT.",
// "@generated" as the first word, or protoc's header; strings, docstrings
// and loose wording never count), and minified scripts (*.min.js, or an
// average line over 500 bytes; never Python). Callers list them with
// AddIgnored (AddPython does so itself) as File.Ignored with the reason, so
// the report shows them as not evaluated; they are never silently dropped.
//
// Known limits: a blueprint or router mounted from another file
// (register_blueprint or include_router across modules) keeps only the
// prefix and dependencies visible in its own file; add_url_rule,
// add_api_route and class-based views are not read; sinks are followed one
// helper deep within the file.
package static
