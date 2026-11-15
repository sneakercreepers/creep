package static

import "strings"

// receiver is a Flask app or blueprint, or a FastAPI app or router, bound to
// a module variable.
type receiver struct {
	framework Framework
	own       mountPrefix // url_prefix= or prefix= on the constructor
	// mounted is set by the first register_blueprint or include_router
	// call; later mounts of the same receiver are ignored.
	mounted bool
	parent  string
	at      mountPrefix // url_prefix= or prefix= on the mount call
	atSet   bool
}

// mountPrefix is a path prefix and what a mount adds to its routes.
type mountPrefix struct {
	path    string
	dynamic bool
	auth    bool // dependencies= holds an auth dependency
}

// collectReceivers finds app and router variables, security schemes and
// mounts anywhere in the file (app factories assign inside functions).
func (x *pyExtraction) collectReceivers(root *Node) {
	var mounts []*Node
	walk(root, func(n *Node) bool {
		switch n.Type {
		case "assignment":
			x.assignment(n)
		case "call":
			if x.isMount(n) {
				mounts = append(mounts, n)
			}
		}
		return true
	})
	for _, m := range mounts {
		x.mount(m)
	}
}

func (x *pyExtraction) assignment(n *Node) {
	left, right := field(n, "left"), field(n, "right")
	if left == nil || right == nil || left.Type != "identifier" || right.Type != "call" {
		return
	}
	name := x.file.text(left)
	callee, method := x.file.resolve(field(right, "function"))
	if !method && strings.HasPrefix(callee, "fastapi.security.") {
		x.authVars[name] = true
		return
	}
	fw, ok := appConstructors[callee]
	if method || !ok {
		return
	}
	_, kw := callArgs(right)
	x.receivers[name] = &receiver{framework: fw, own: x.prefixArgs(fw, kw)}
}

// isMount matches register_blueprint and include_router calls.
func (x *pyExtraction) isMount(call *Node) bool {
	fn := field(call, "function")
	if fn == nil || fn.Type != "attribute" {
		return false
	}
	verb := x.file.text(field(fn, "attribute"))
	return verb == "register_blueprint" || verb == "include_router"
}

// mount records `parent.register_blueprint(child, url_prefix=...)` or
// `parent.include_router(child, prefix=..., dependencies=...)` when both
// sides are known receivers.
func (x *pyExtraction) mount(call *Node) {
	obj := field(field(call, "function"), "object")
	pos, kw := callArgs(call)
	if obj == nil || obj.Type != "identifier" || len(pos) == 0 || pos[0].Type != "identifier" {
		return
	}
	parent, child := x.file.text(obj), x.file.text(pos[0])
	r := x.receivers[child]
	if r == nil || r.mounted || x.receivers[parent] == nil || parent == child {
		return
	}
	r.mounted, r.parent = true, parent
	r.at = x.prefixArgs(r.framework, kw)
	r.atSet = keyword(x.file, kw, "url_prefix", "prefix") != nil
}

// prefixArgs reads the prefix and dependencies keywords of a constructor or
// mount call.
func (x *pyExtraction) prefixArgs(fw Framework, kw []*Node) mountPrefix {
	var p mountPrefix
	name := "prefix"
	if fw == Flask {
		name = "url_prefix"
	}
	if v := keyword(x.file, kw, name); v != nil {
		s, ok := x.file.literalString(v)
		p.path, p.dynamic = capText(s, maxPathBytes), !ok
	}
	p.auth = x.depsAuth(keyword(x.file, kw, "dependencies"))
	return p
}

// prefix is prefixOf memoized per receiver, so many routes on a deep mount
// chain compose it once.
func (x *pyExtraction) prefix(name string) mountPrefix {
	if p, ok := x.prefixes[name]; ok {
		return p
	}
	p := x.prefixOf(name, 0)
	x.prefixes[name] = p
	return p
}

// prefixOf composes a receiver's prefix with those of the receivers it is
// mounted on. A Flask mount's url_prefix replaces the blueprint's own; a
// FastAPI include prefix is prepended to the router's.
func (x *pyExtraction) prefixOf(name string, depth int) mountPrefix {
	r := x.receivers[name]
	if r == nil {
		return mountPrefix{}
	}
	own := r.own
	if !r.mounted {
		return own
	}
	if depth >= maxMountDepth {
		return mountPrefix{dynamic: true, auth: own.auth}
	}
	parent := x.prefixOf(r.parent, depth+1)
	switch {
	case r.framework == Flask && r.atSet:
		own = mountPrefix{path: r.at.path, dynamic: r.at.dynamic, auth: own.auth}
	default:
		own.path = joinPath(r.at.path, own.path)
		own.dynamic = own.dynamic || r.at.dynamic
	}
	return mountPrefix{
		path:    joinPath(parent.path, own.path),
		dynamic: parent.dynamic || own.dynamic,
		auth:    parent.auth || own.auth || r.at.auth,
	}
}

// depsAuth reports whether a dependencies=[...] list holds an auth dependency.
func (x *pyExtraction) depsAuth(list *Node) bool {
	if list == nil {
		return false
	}
	for _, c := range namedChildren(list) {
		if c.Type == "call" && x.dependencyAuth(c) {
			return true
		}
	}
	return false
}

// dependencyAuth: Security(...) always counts; Depends(f) counts when f is a
// security scheme variable or has an auth-like name.
func (x *pyExtraction) dependencyAuth(call *Node) bool {
	switch lastSegment(x.calleeName(call)) {
	case "Security":
		return true
	case "Depends":
	default:
		return false
	}
	pos, kw := callArgs(call)
	arg := firstArg(pos, kw)
	if arg == nil {
		return false
	}
	if arg.Type == "identifier" && x.authVars[x.file.text(arg)] {
		return true
	}
	return authName(x.calleeName(arg))
}

// paramsAuth finds Depends or Security in a handler's parameters, including
// inside Annotated[...] types.
func (x *pyExtraction) paramsAuth(def *Node) bool {
	params := field(def, "parameters")
	found := false
	if params == nil {
		return false
	}
	walk(params, func(n *Node) bool {
		if !found && n.Type == "call" && x.dependencyAuth(n) {
			found = true
		}
		return !found
	})
	return found
}
