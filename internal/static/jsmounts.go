package static

import "strings"

// maxScopedUses caps the path-scoped auth middleware kept per receiver, so a
// hostile file cannot make every route scan an unbounded list. Uses past
// the cap are dropped, which can only hide auth, never claim it.
const maxScopedUses = 64

// noUse marks a receiver with no auth middleware used without a path.
const noUse = ^uint32(0)

// jsReceiver is an Express app or router bound to a variable.
type jsReceiver struct {
	// mounted is set by the first parent.use(path, ..., router) call; later
	// mounts of the same router are ignored.
	mounted bool
	parent  string
	// at is the mount path; at.auth is set when middleware before the
	// router in the mount call looks like auth.
	at    mountPrefix
	atPos uint32
	// openAuth is where the first auth middleware used without a path
	// starts, or noUse.
	openAuth uint32
	scoped   []authUse
}

// authUse is auth middleware used on a path prefix: use("/admin", auth).
type authUse struct {
	pos    uint32
	prefix string
}

// collectReceivers finds express() apps and Router() routers anywhere in the
// file (app factories assign inside functions), then reads their use and
// all calls in source order.
func (x *jsExtraction) collectReceivers(root *Node) {
	var uses []*Node
	walk(root, func(n *Node) bool {
		switch n.Type {
		case "variable_declarator":
			x.addReceiver(field(n, "name"), field(n, "value"))
		case "assignment_expression":
			x.addReceiver(field(n, "left"), field(n, "right"))
		case "call_expression":
			uses = append(uses, n)
		}
		return true
	})
	for _, call := range uses {
		x.use(call)
	}
}

// addReceiver records `app = express()` and `router = express.Router()`,
// also through a chain such as `app = module.exports = express()`.
func (x *jsExtraction) addReceiver(name, value *Node) {
	for value != nil && value.Type == "assignment_expression" {
		value = field(value, "right")
	}
	if name == nil || name.Type != "identifier" || value == nil || value.Type != "call_expression" {
		return
	}
	callee, method := x.file.resolve(field(value, "function"))
	if method || (callee != "express" && callee != "express.Router") {
		return
	}
	x.receivers[x.file.text(name)] = &jsReceiver{openAuth: noUse}
}

// use reads `recv.use([path,] ...middleware)`, which either mounts a router
// or adds middleware, and `recv.all(path, ...auth)`, which guards a path.
func (x *jsExtraction) use(call *Node) {
	fn := field(call, "function")
	obj := field(fn, "object")
	if fn == nil || fn.Type != "member_expression" || obj == nil || obj.Type != "identifier" {
		return
	}
	parent := x.file.text(obj)
	r := x.receivers[parent]
	args := jsArgs(call)
	if r == nil || len(args) == 0 {
		return
	}
	switch x.file.text(field(fn, "property")) {
	case "use":
		x.useCall(r, parent, call.StartByte, args)
	case "all":
		if len(args) > 1 && x.allAuth(flattenArgs(args[1:])) {
			r.addAuth(x.usePath(args[0]), call.StartByte)
		}
	}
}

func (x *jsExtraction) useCall(r *jsReceiver, parent string, pos uint32, args []*Node) {
	var at mountPrefix
	hasPath := isPathArg(args[0])
	if hasPath {
		at = x.usePath(args[0])
		args = args[1:]
	}
	stack := flattenArgs(args)
	for i, m := range stack {
		if m.Type != "identifier" || x.receivers[x.file.text(m)] == nil {
			at.auth = at.auth || x.authMiddleware(m)
			continue
		}
		if i > 0 && !hasPath && x.maybePrefix(stack[0]) {
			at.path, at.dynamic = "", true // use(PREFIX, router): unknown path, not middleware
		}
		x.mount(parent, x.file.text(m), at, pos)
		return
	}
	if at.auth {
		r.addAuth(at, pos)
	}
}

// isPathArg reports whether a first use() argument is a path, not
// middleware: Express treats any non-function there as a path.
func isPathArg(n *Node) bool {
	switch n.Type {
	case "string", "template_string", "regex", "array", "binary_expression":
		return true
	}
	return false
}

// usePath reads a use() or all() path, capped at maxPathBytes; a trailing
// "*" or "/*" is the same prefix, any other pattern makes it dynamic.
func (x *jsExtraction) usePath(n *Node) mountPrefix {
	s, ok := x.file.literalString(n)
	s = strings.TrimSuffix(strings.TrimSuffix(s, "*"), "/")
	if !ok || strings.ContainsAny(s, "*?+()[]") {
		return mountPrefix{dynamic: true}
	}
	return mountPrefix{path: s}
}

// maybePrefix: a name in front of a router that is not a function, import
// or auth middleware of this file is probably a path constant.
func (x *jsExtraction) maybePrefix(n *Node) bool {
	if n.Type != "identifier" && n.Type != "member_expression" {
		return false
	}
	name := x.file.text(n)
	_, imported := x.file.imports[name]
	return x.file.funcs[name] == nil && !imported && !x.authMiddleware(n)
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

// mount records the first mount of child on parent.
func (x *jsExtraction) mount(parent, child string, at mountPrefix, pos uint32) {
	c := x.receivers[child]
	if c == nil || c.mounted || parent == child {
		return
	}
	at.path = capText(at.path, maxPathBytes)
	c.mounted, c.parent, c.at, c.atPos = true, parent, at, pos
}

// prefix composes a receiver's mount paths, memoized per receiver.
func (x *jsExtraction) prefix(name string) mountPrefix {
	if p, ok := x.prefixes[name]; ok {
		return p
	}
	var p mountPrefix
	for depth, cur := 0, name; ; depth++ {
		r := x.receivers[cur]
		if r == nil || !r.mounted {
			break
		}
		if depth >= maxMountDepth {
			p.dynamic = true
			break
		}
		p.path = joinPath(r.at.path, p.path)
		p.dynamic = p.dynamic || r.at.dynamic
		cur = r.parent
	}
	x.prefixes[name] = p
	return p
}

// receiverAuth reports whether auth middleware guards a route declared at
// pos with the given router-local path: used before it on its receiver
// (on all paths, or on a prefix of a known path), on the mount of its
// router, or before that mount on the parent, up the mount chain.
func (x *jsExtraction) receiverAuth(recv, path string, known bool, pos uint32) bool {
	for range maxMountDepth + 1 {
		r := x.receivers[recv]
		if r == nil {
			return false
		}
		known = known && len(path) < maxPathBytes
		if r.covers(path, known, pos) {
			return true
		}
		if !r.mounted {
			return false
		}
		if r.at.auth {
			return true
		}
		path, known = joinPath(r.at.path, path), known && !r.at.dynamic
		recv, pos = r.parent, r.atPos
	}
	return false
}

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
