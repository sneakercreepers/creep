package static

// receiverEscapes reports whether a known Flask or FastAPI app, Blueprint
// or APIRouter is used other than in a form the extractor reads, or whether
// a module is imported dynamically in a form the literal resolver does not
// read (#255 maintainer decision). Either can reach a route or a sink
// static does not see (builtins.getattr, an aliased getattr, attrgetter,
// vars(app), a function-local __import__), so the caller marks the file
// not evaluated in full. pyBenignUses lists what is read. A dynamic import
// counts only in a file with routes (hasRoutes): a sink matters only in a
// route, and static follows no call into another file, so library code
// that loads plugins stays vendor.
func (x *pyExtraction) receiverEscapes(root *Node, hasRoutes bool) bool {
	parents := parentsOf(root)
	escaped := false
	walk(root, func(n *Node) bool {
		switch {
		case escaped || n.Type == "import_statement" || n.Type == "import_from_statement":
			return false
		case n.Type == "identifier" && x.receivers[x.file.text(n)] != nil:
			escaped = !x.benignUse(n, parents)
		case n.Type == "call" && hasRoutes:
			escaped = x.unreadImport(n, parents)
		}
		return !escaped
	})
	return escaped
}

// pyBenignUses are the reads of a receiver that reach no route: any method
// call (decorators, app.run(...), app.register_blueprint(bp)), a bare
// decorator (@app.teardown_appcontext), the
// attributes in pyBenignAttrs (app.config[...] and the like), an
// assignment to the name, a parameter, return app, the receiver argument
// of register_blueprint, include_router or mount (a mount), of getattr
// called at once (attrKey), of uvicorn.run and of flask_cors.CORS.
func (x *pyExtraction) benignUse(n *Node, parents map[*Node]*Node) bool {
	p := parents[n]
	if p == nil {
		return false
	}
	switch p.Type {
	case "assignment":
		return n.Field == "left"
	case "parameters", "typed_parameter", "default_parameter", "typed_default_parameter", "return_statement", "global_statement":
		return true
	case "attribute":
		return n.Field == "object" && (calledMember(p, parents, "call") || parentType(p, parents) == "decorator" || pyBenignAttrs[x.file.text(field(p, "attribute"))])
	case "argument_list":
		return x.benignArgument(parents[p], parents)
	}
	return false
}

// unwrapParens strips the parentheses around an expression.
func unwrapParens(n *Node) *Node {
	for n != nil && n.Type == "parenthesized_expression" && len(namedChildren(n)) == 1 {
		n = namedChildren(n)[0]
	}
	return n
}

func parentType(n *Node, parents map[*Node]*Node) string {
	if p := parents[n]; p != nil {
		return p.Type
	}
	return ""
}

var pyBenignAttrs = map[string]bool{
	"config": true, "logger": true, "secret_key": true, "debug": true, "testing": true,
	"name": true, "state": true, "extensions": true, "jinja_env": true, "wsgi_app": true,
}

var pyMountMethods = map[string]bool{"register_blueprint": true, "include_router": true, "mount": true}

var pyBenignCallees = map[string]bool{"uvicorn.run": true, "flask_cors.CORS": true}

func (x *pyExtraction) benignArgument(call *Node, parents map[*Node]*Node) bool {
	if call == nil || call.Type != "call" {
		return false
	}
	name, method := x.file.resolve(field(call, "function"))
	switch {
	case method:
		return pyMountMethods[name]
	case name == "getattr":
		return calledMember(call, parents, "call")
	}
	return pyBenignCallees[name]
}

// unreadImport reports a dynamic import the resolver does not read: one
// that is neither the root of a called attribute chain nor the value of a
// module-level assignment (dynamicImport, addDynamicImport). Its module
// could hold any sink.
func (x *pyExtraction) unreadImport(call *Node, parents map[*Node]*Node) bool {
	if _, _, ok := x.file.dynamicImport(call); !ok {
		return false
	}
	p := parents[call]
	switch {
	case p == nil:
		return true
	case p.Type == "attribute" && call.Field == "object":
		return false
	case p.Type == "assignment" && call.Field == "right":
		stmt := parents[p]
		return stmt == nil || parents[stmt] == nil || parents[stmt].Type != "module"
	}
	return true
}
