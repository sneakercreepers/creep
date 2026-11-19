package static

import (
	"path"
	"strings"
)

// pyUses judges every use of a known Flask or FastAPI app, Blueprint or
// APIRouter in one file.
type pyUses struct {
	x       *pyExtraction
	parents map[*Node]*Node
	// factories holds the names of functions that return a receiver; each
	// call of one is a use of that receiver.
	factories map[string]bool
	escaped   bool
}

// receiverEscapes reports whether a known Flask or FastAPI app, Blueprint
// or APIRouter is used other than in a form the extractor reads, or whether
// a module is imported dynamically in a form the literal resolver does not
// read (#255 maintainer decision). Either can reach a route or a sink
// static does not see (builtins.getattr, an aliased getattr, attrgetter,
// vars(app), a function-local __import__, reg.mount(app) on an object that
// is no app), so the caller marks the file not evaluated in full.
// benignUse lists what is read. A dynamic import counts only in a file
// with routes (hasRoutes): a sink matters only in a route, and static
// follows no call into another file, so library code that loads plugins
// stays vendor.
func (x *pyExtraction) receiverEscapes(root *Node, hasRoutes bool) bool {
	u := &pyUses{x: x, parents: parentsOf(root), factories: map[string]bool{}}
	walk(root, func(n *Node) bool {
		switch {
		case u.escaped || n.Type == "import_statement" || n.Type == "import_from_statement":
			return false
		case n.Type == "identifier" && x.receivers[x.file.text(n)] != nil:
			u.escaped = !u.benignUse(n)
		case n.Type == "call" && hasRoutes:
			u.escaped = x.unreadImport(n, u.parents)
		}
		return !u.escaped
	})
	if !u.escaped && len(u.factories) > 0 {
		walk(root, func(n *Node) bool {
			if n.Type == "import_statement" || n.Type == "import_from_statement" {
				return false
			}
			u.escaped = u.escaped || n.Type == "identifier" && u.factories[x.file.text(n)] && !u.factoryUse(n)
			return !u.escaped
		})
	}
	return u.escaped
}

// benignUse covers the reads of a receiver that reach no route: any method
// call (decorators, app.run(...), app.register_blueprint(bp)), a bare
// decorator (@app.teardown_appcontext), the attributes in pyBenignAttrs
// (app.config[...] and the like), an assignment to the name, a parameter,
// return app in a module-level function whose calls are themselves benign
// (factoryUse), the argument of register_blueprint, include_router or
// mount called on a known app or router (a mount), of the builtin getattr
// called at once (attrKey), and of uvicorn.run and flask_cors.CORS
// imported from those packages.
func (u *pyUses) benignUse(n *Node) bool {
	p := u.parents[n]
	if p == nil {
		return false
	}
	switch p.Type {
	case "assignment":
		return n.Field == "left"
	case "parameters", "typed_parameter", "default_parameter", "typed_default_parameter", "global_statement":
		return true
	case "return_statement":
		return u.addFactory(p)
	case "attribute":
		return n.Field == "object" && (calledMember(p, u.parents, "call") || parentType(p, u.parents) == "decorator" || pyBenignAttrs[u.x.file.text(field(p, "attribute"))])
	case "argument_list":
		return u.benignArgument(u.parents[p])
	}
	return false
}

var pyBenignAttrs = map[string]bool{
	"config": true, "logger": true, "secret_key": true, "debug": true, "testing": true,
	"name": true, "state": true, "extensions": true, "jinja_env": true, "wsgi_app": true,
}

var pyMountMethods = map[string]bool{"register_blueprint": true, "include_router": true, "mount": true}

// pyBenignCallees take an app and reach no route. Their packages are
// trusted only when the repository holds no module of the same name
// (ShadowsTrustedModule), since Python imports the script's own directory
// first.
var pyBenignCallees = map[string]bool{"uvicorn.run": true, "flask_cors.CORS": true}

func (u *pyUses) benignArgument(call *Node) bool {
	if call == nil || call.Type != "call" {
		return false
	}
	fn := field(call, "function")
	name, method := u.x.file.resolve(fn)
	switch {
	case method:
		obj := field(fn, "object")
		return pyMountMethods[name] && obj != nil && obj.Type == "identifier" && u.x.receivers[u.x.file.text(obj)] != nil
	case name == "getattr":
		return u.x.file.funcs["getattr"] == nil && calledMember(call, u.parents, "call")
	}
	return pyBenignCallees[name]
}

// ShadowsTrustedModule reports whether a repo-relative Python path is a
// module named like a package whose call static trusts with an app
// (uvicorn, flask_cors): such a file would be imported in its place, so
// callers mark it not evaluated in full (#255 tester cycle 6).
func ShadowsTrustedModule(rel string) bool {
	base := path.Base(rel)
	if base == "__init__.py" || base == "__init__.pyi" {
		base = path.Base(path.Dir(rel))
	}
	base = strings.TrimSuffix(strings.TrimSuffix(base, ".pyi"), ".py")
	for callee := range pyBenignCallees {
		if base == callee[:strings.IndexByte(callee, '.')] {
			return true
		}
	}
	return false
}

// addFactory records the function that holds a `return app`, so its calls
// are judged as uses of the app (#255 tester cycle 6). A return from a
// lambda or a method has no name to follow and escapes.
func (u *pyUses) addFactory(ret *Node) bool {
	name := ""
	for n := u.parents[ret]; n != nil && name == ""; n = u.parents[n] {
		switch n.Type {
		case "lambda", "class_definition", "module":
			return false
		case "function_definition":
			name = u.x.file.text(field(n, "name"))
		}
	}
	if name == "" || u.inClass(ret) {
		return false
	}
	u.factories[name] = true
	return true
}

func (u *pyUses) inClass(n *Node) bool {
	for ; n != nil; n = u.parents[n] {
		if n.Type == "class_definition" {
			return true
		}
	}
	return false
}

// factoryUse reports whether a name of a function that returns a receiver
// sits where it reaches no route: its own definition, or a call whose
// result is discarded or only run (create_app().run()). @mk().route(...),
// app = create_app() and passing the function itself escape.
func (u *pyUses) factoryUse(n *Node) bool {
	p := u.parents[n]
	switch {
	case p == nil:
		return false
	case p.Type == "function_definition":
		return n.Field == "name"
	case p.Type != "call" || n.Field != "function":
		return false
	}
	q := u.parents[p]
	switch {
	case q == nil:
		return false
	case q.Type == "expression_statement":
		return true
	case q.Type == "attribute" && p.Field == "object":
		return u.x.file.text(field(q, "attribute")) == "run" && calledMember(q, u.parents, "call")
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
