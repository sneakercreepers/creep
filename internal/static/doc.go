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
// An Extractor turns Python trees into a Graph of Flask and FastAPI routes
// (AddPython) and JavaScript, TypeScript and TSX trees into a Graph of
// Express routes (AddJavaScript), with the sinks their handlers reach (SQL,
// NoSQL, shell, file, HTTP client, template) and how auth was seen
// (decorator, dependency, call, middleware). Graph holds only IDs, enums,
// booleans and counts, so it can go to the planner; paths, handler names and
// lines go to a separate Locations value for the report. Extraction works
// per file, from syntax alone: imports and requires resolve aliases,
// blueprints and routers compose prefixes within the file, and auth is a
// name-based hint.
//
// Express auth is middleware, read in source order as Express runs it:
// per-route middleware before the handler (also in arrays and on
// app.route() chains after an auth .all()), auth used on the app or router
// before the route (app.use(auth), or app.use("/admin", auth) and
// app.all("/admin/*", auth) for routes under that path segment), and auth
// placed before a router in its mount call (app.use("/api", auth, router))
// or used on the parent before the mount. A use() after a route, auth after
// the handler, a dynamic or possibly dynamic guard path (use(PREFIX, auth),
// use(prefix(), auth)) or a mount chain past the depth cap never claims
// auth. Auth is syntactic: a use() under a condition still counts.
//
// Receivers resolve by declaration: a name refers to the express() or
// Router() bound in its innermost enclosing function, a parameter or other
// value of that name shadows it, and a reassigned name or one bound twice in
// a function claims no auth. A router mounted several times yields one
// route per mount chain (up to maxMountPaths, past it the route is
// partial), so a public mount stays public. A router that is mounted in the
// file and also escapes (an alias, a helper argument, an export) may have
// mounts the file does not show, so its routes are partial and claim no
// auth from its mounts or above them; its own use() auth still holds.
//
// A receiver imported from a module of the repository (a relative or
// absolute path, or an @/ or ~/ alias: ./models/User, ../db) is an unknown
// object from another file, so its method calls match the "." sink specs
// as a variable's do (User.findOne, db.query; .find takes any filter but a
// callback there). Any other call into such a module (svc.createUser,
// getUser) runs code the scan cannot see and makes the route partial.
// Package imports never fall back to method names, so ReactDOM.render is
// not a template sink.
//
// Every entry of a route's argument list is analyzed: inline and same-file
// middleware, same-file factories and wrappers such as asyncHandler(fn), and
// the handler (the last entry that is not auth middleware); sinks of all of
// them belong to the route, and each scan covers nested callbacks. An entry
// that is neither a function of the file nor recognized auth middleware (an
// imported controller, upload.single()) is code the scan cannot see, so the
// route and file are marked partial. Calls on an unknown receiver count as
// routes only when the file imports express, the path is a literal starting
// with "/" or "*", the receiver is a local name and the handler is a
// function of the file.
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
// JavaScript follows the same rule over the whole handler, closures
// included: only `const|let|var name = value` and `name = value` with a
// string, template literal without substitutions, number, boolean, null or
// a + of them keep a name constant; a declarator without a value,
// destructuring, for-in/of, catch, ++, augmented assignment, parameters and
// function or class names make it dynamic, and with or a direct eval makes
// every name dynamic. Arrays and objects count only when written in the
// sink call, without spreads or computed keys.
//
// Every walk is iterative, every per-route list and string is capped, and
// argument analysis is memoized per name under a per-file visit budget
// (past it, sinks count as dynamic and the route and file are marked
// partial), so a hostile file costs linear time and bounded memory.
// JavaScript handler scans share a second per-file visit budget, since a
// scan covers nested functions; a cut scan marks its sinks dynamic and its
// route and file partial.
//
// IgnoreReason names files that may not need evaluating: vendor
// directories (vendor, node_modules, site-packages, virtualenvs and the
// like, matched on directory segments of a repo-relative path; absolute or
// escaping paths are an error), files whose leading comment block carries
// an exact generator marker ("Code generated ... DO NOT EDIT.",
// "@generated" as the first word, or protoc's header; strings, docstrings
// and loose wording never count), and minified scripts (nine tenths of the
// bytes on lines over 500 bytes; never Python; a .min.js name never
// counts). These marks are the author's say-so (pentest P4, #213), so
// AddPython and AddJavaScript believe one only for a file that parsed
// without errors and holds no route, and list it as File.Ignored with the
// reason; a file with a route is extracted as usual. Callers may list a
// vendor file with AddIgnored without parsing it only when VendorEvidence
// names a package-manager mark that exists and MayHoldRoute, a byte test
// that errs only toward true, says the file cannot hold a route; a mark is
// a repository file too, so it never hides a route (#213). A mark also
// vouches for the C, C++ and component sources its packages ship, which
// callers list as vendor only when MayHoldAnyRoute is false (#261). For a
// declaration file (.d.ts) of such a tree, AddDeclaration also lists it as
// vendor when it does not parse, since the grammar lags TypeScript's type
// syntax, but only when its code, comments aside, cannot hold a route
// (#262). Ignored files are never silently dropped.
//
// Names are read as the runtime reads them (#259): Python identifiers are
// folded with nfkcASCII, the code points whose NFKC form is ASCII, and
// JavaScript escapes in identifiers and literals are decoded (cookJS), so
// @app.ｒｏｕｔｅ and app.get spelled with escapes match. MayHoldRoute folds
// and decodes the same way. app["get"] and getattr(app, "route") with a
// literal name are the dot form; a name that is not a literal on a known
// app or router makes the route partial, and so does a call through a
// module imported by __import__ or importlib.import_module of a computed
// name. Any other use of a known app or router (passed, stored,
// destructured, reached through .call or an aliased getattr), and in a
// file with routes an unread dynamic import, marks the file truncated
// (receiverEscapes in escape.go and pyescape.go, which list the benign
// uses).
//
// DetectScanners looks the optional external scanners (gitleaks,
// osv-scanner, semgrep) up on PATH and never runs them (ADR 0010). The
// first match decides, and one in a relative PATH entry is refused. A
// match is resolved to its final path (links and junctions followed, \\?\
// removed), and OutsideRepo refuses it when that path or a directory above
// it is the repository or the current directory, compared by file identity
// (ADR 0013). internal/scanrun runs only that final path.
//
// Known limits: a blueprint or router mounted from another file
// (register_blueprint, include_router or app.use across modules) keeps only
// the prefix, dependencies and middleware visible in its own file;
// add_url_rule, add_api_route and class-based views are not read; sinks are
// followed one helper deep within the file, and an Express handler imported
// from another file has no sinks (its route is partial). Function scope is
// the unit for receivers, so block-scoped twins in one function are
// ambiguous. Prototype pollution (a computed-key write)
// is not a sink kind: the planner sees its route only. Array.find shares
// MongoDB's name, so .find counts only with an object literal filter.
package static
