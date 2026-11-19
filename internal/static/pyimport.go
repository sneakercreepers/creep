package static

import "strings"

// dynamicImports are the calls that import a module named by a string.
var dynamicImports = map[string]bool{"__import__": true, "importlib.import_module": true}

// dynamicImport reports whether n calls __import__ or
// importlib.import_module, and the module the result is when its name is a
// literal (#255 tester I3). __import__("a.b") returns the top package a.
func (f *pyFile) dynamicImport(n *Node) (module string, literal, ok bool) {
	if n == nil || n.Type != "call" || !plainCallee(field(n, "function")) {
		return "", false, false
	}
	callee, method := f.resolve(field(n, "function"))
	if method || !dynamicImports[callee] {
		return "", false, false
	}
	pos, _ := callArgs(n)
	if len(pos) == 0 {
		return "", false, true
	}
	raw, lit := f.literalString(pos[0])
	module, plain := pyUnescape(raw)
	if callee == "__import__" {
		module, _, _ = strings.Cut(module, ".")
	}
	return module, lit && plain && module != "", true
}

// plainCallee reports whether fn is a name or name.attr, the only shapes
// an import function takes. resolve on anything deeper could recurse
// through a chain of calls, quadratic in a hostile file.
func plainCallee(fn *Node) bool {
	if fn != nil && fn.Type == "attribute" {
		fn = field(fn, "object")
	}
	return fn != nil && fn.Type == "identifier"
}

// addDynamicImport records a module-level `name = __import__("os")` as an
// import of os, and a name bound to an import that is not a literal as
// dynamic, so calls through it are not read as plain method calls.
func (f *pyFile) addDynamicImport(stmt *Node) {
	if stmt.Type != "expression_statement" || len(namedChildren(stmt)) != 1 {
		return
	}
	a := namedChildren(stmt)[0]
	left := field(a, "left")
	if a.Type != "assignment" || left == nil || left.Type != "identifier" {
		return
	}
	module, literal, ok := f.dynamicImport(field(a, "right"))
	switch {
	case !ok:
	case literal:
		f.imports[f.text(left)] = module
	default:
		f.dynamicModules[f.text(left)] = true
	}
}

// dynamicCallee reports whether fn is an attribute of a module imported by
// a name that is not a literal: it could be any sink, so the caller marks
// the route partial.
func (f *pyFile) dynamicCallee(fn *Node) bool {
	if fn == nil || fn.Type != "attribute" {
		return false
	}
	n := fn
	for n != nil && n.Type == "attribute" {
		n = field(n, "object")
	}
	if n != nil && n.Type == "identifier" {
		return f.dynamicModules[f.text(n)]
	}
	_, literal, ok := f.dynamicImport(n)
	return ok && !literal
}

// callsDynamicModule reports whether a function body calls through a
// dynamically imported module (dynamicCallee).
func (x *pyExtraction) callsDynamicModule(def *Node) bool {
	for _, call := range x.scan(def).calls {
		if x.file.dynamicCallee(field(call, "function")) {
			return true
		}
	}
	return false
}
