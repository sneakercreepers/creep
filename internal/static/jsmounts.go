package static

import "strings"

// maxScopedUses caps the path-scoped auth middleware kept per receiver, so a
// hostile file cannot make every route scan an unbounded list. Uses past
// the cap are dropped, which can only hide auth, never claim it.
const maxScopedUses = 64

// noUse marks a receiver with no auth middleware used without a path.
const noUse = ^uint32(0)

// jsReceiver is an Express app or router bound by one declaration.
type jsReceiver struct {
	// ambiguous is set when the binding is reassigned or shares its scope
	// with another binding of the name; it then claims no auth.
	ambiguous bool
	// mounts lists every parent.use(path, ..., router) of this router, up
	// to maxMountPaths; mountOverflow marks the rest.
	mounts        []jsMount
	mountOverflow bool
	// openAuth is where the first auth middleware used without a path
	// starts, or noUse.
	openAuth uint32
	scoped   []authUse
	// chains memoizes chainsOf.
	chains                          []mountChain
	chainsPartial, chainsDone, busy bool
}

func newReceiver() *jsReceiver { return &jsReceiver{openAuth: noUse} }

// jsMount is one mount of a router: its parent, the mount path, whether
// auth middleware sits before the router in the mount call, and where the
// call starts.
type jsMount struct {
	parent *jsReceiver
	at     mountPrefix
	pos    uint32
}

// authUse is auth middleware used on a path prefix: use("/admin", auth).
type authUse struct {
	pos    uint32
	prefix string
}

// collectReceivers resolves receivers by scope, then reads their use and
// all calls in source order.
func (x *jsExtraction) collectReceivers(root *Node) {
	x.collectBindings(root)
	if len(x.bind) == 0 {
		return
	}
	walk(root, func(n *Node) bool {
		if n.Type == "call_expression" {
			x.use(n)
		}
		return true
	})
}

// use reads `recv.use([path,] ...middleware)`, which mounts routers and adds
// middleware, and `recv.all(path, ...auth)`, which guards a path.
func (x *jsExtraction) use(call *Node) {
	fn := field(call, "function")
	if fn == nil || fn.Type != "member_expression" {
		return
	}
	r := x.receiverRef(field(fn, "object"))
	args := jsArgs(call)
	if r == nil || len(args) == 0 {
		return
	}
	switch x.file.text(field(fn, "property")) {
	case "use":
		x.useCall(r, call.StartByte, args)
	case "all":
		if len(args) > 1 && x.allAuth(flattenArgs(args[1:])) {
			r.addAuth(x.usePath(args[0]), call.StartByte)
		}
	}
}

// useCall mounts each router in the call with the auth middleware seen
// before it, and records auth middleware for routes declared later.
func (x *jsExtraction) useCall(r *jsReceiver, pos uint32, args []*Node) {
	var at mountPrefix
	switch {
	case isPathArg(args[0]):
		at, args = x.usePath(args[0]), args[1:]
	case len(args) > 1 && x.possiblePath(args[0]):
		at, args = mountPrefix{dynamic: true}, args[1:] // use(PREFIX, ...): unknown path
	}
	for _, m := range flattenArgs(args) {
		if child := x.receiverRef(m); child != nil {
			x.mount(r, child, at, pos)
			continue
		}
		at.auth = at.auth || x.authMiddleware(m)
	}
	if at.auth {
		r.addAuth(at, pos)
	}
}

// isPathArg reports whether a first use() argument is a path, not
// middleware: Express treats any non-function there as a path.
func isPathArg(n *Node) bool {
	switch unwrapCast(n).Type {
	case "string", "template_string", "regex", "array", "binary_expression":
		return true
	}
	return false
}

// usePath reads a use() or all() path, capped at maxPathBytes; a trailing
// "*" or "/*" is the same prefix, any other pattern makes it dynamic.
func (x *jsExtraction) usePath(n *Node) mountPrefix {
	s, ok := x.file.literalString(unwrapCast(n))
	s = strings.TrimSuffix(strings.TrimSuffix(s, "*"), "/")
	if !ok || strings.ContainsAny(s, "*?+()[]") {
		return mountPrefix{dynamic: true}
	}
	return mountPrefix{path: s}
}

// possiblePath: a first use() argument that may hold a path rather than
// middleware: a name or call that is not a router, a function or import of
// this file, or auth middleware. Library factories such as express.json()
// resolve to an import and stay middleware.
func (x *jsExtraction) possiblePath(n *Node) bool {
	n = unwrapCast(n)
	if x.receiverRef(n) != nil || x.authMiddleware(n) {
		return false
	}
	switch n.Type {
	case "call_expression":
		return !x.file.imported(field(n, "function"))
	case "identifier", "member_expression":
		name := x.file.text(n)
		_, imported := x.file.imports[name]
		return x.file.funcs[name] == nil && !imported
	}
	return false
}

// allAuth reports whether every handler of an all() call is auth.
func (x *jsExtraction) allAuth(stack []*Node) bool {
	for _, m := range stack {
		if !x.authMiddleware(m) {
			return false
		}
	}
	return len(stack) > 0
}

// addAuth records auth middleware at pos on a path prefix ("" for all
// paths). A dynamic or capped prefix is never recorded: it might not cover
// a route.
func (r *jsReceiver) addAuth(at mountPrefix, pos uint32) {
	switch {
	case at.dynamic || len(at.path) >= maxPathBytes:
	case at.path == "":
		r.openAuth = min(r.openAuth, pos)
	case len(r.scoped) < maxScopedUses:
		r.scoped = append(r.scoped, authUse{pos: pos, prefix: at.path})
	}
}

// mount records one mount of child on parent; every mount is kept.
func (x *jsExtraction) mount(parent, child *jsReceiver, at mountPrefix, pos uint32) {
	if child == parent {
		return
	}
	if len(child.mounts) == maxMountPaths {
		child.mountOverflow = true
		return
	}
	at.path = capText(at.path, maxPathBytes)
	child.mounts = append(child.mounts, jsMount{parent: parent, at: at, pos: pos})
}

// covers reports whether auth middleware used on r before pos guards path.
func (r *jsReceiver) covers(path string, known bool, pos uint32) bool {
	if r.openAuth < pos {
		return true
	}
	for _, u := range r.scoped {
		if u.pos >= pos {
			return false
		}
		if known && (path == u.prefix || strings.HasPrefix(path, u.prefix+"/")) {
			return true
		}
	}
	return false
}
