package static

import (
	"path"
	"strings"
)

// maxHandlerWraps bounds how many wrapper calls such as
// asyncHandler(async (req, res) => ...) are unwrapped to find a handler.
const maxHandlerWraps = 4

// methodsAll is what app.all matches: every method, named or not.
const methodsAll = MethodGet | MethodPost | MethodPut | MethodPatch | MethodDelete | MethodHead | MethodOptions | MethodTrace | MethodOther

// jsExtraction is the state of extracting Express routes from one file.
type jsExtraction struct {
	file *jsFile
	// bind holds the bindings of each receiver name (jsscope.go);
	// overloaded names passed maxNameBindings and resolve to nothing.
	bind       map[string][]binding
	overloaded map[string]bool
	chains     map[*Node]routeBase
	handlers   map[*Node]handlerFacts
	helpers    map[*Node][]foundSink
	scans      map[*Node]*jsScan
	// constBudget bounds DynamicArg analysis and scanBudget bounds handler
	// scans (jsbind.go).
	constBudget, scanBudget int
}

// routeBase is the receiver and path of a route call or app.route(path)
// chain.
type routeBase struct {
	name    string      // receiver variable, "" when not a plain name
	recv    *jsReceiver // nil when not a known app or router
	path    *Node
	allAuth bool // an earlier .all(...) link in the chain holds auth middleware
	ok      bool
}

func extractJavaScript(root *Node, src []byte, lim extractLimits) (routes []foundRoute, truncated bool) {
	x := &jsExtraction{
		file:        newJSFile(root, src),
		bind:        map[string][]binding{},
		overloaded:  map[string]bool{},
		chains:      map[*Node]routeBase{},
		handlers:    map[*Node]handlerFacts{},
		helpers:     map[*Node][]foundSink{},
		scans:       map[*Node]*jsScan{},
		constBudget: lim.constVisits,
		scanBudget:  lim.scanVisits,
	}
	x.collectReceivers(root)
	walk(root, func(n *Node) bool {
		if truncated || n.Type != "call_expression" {
			return !truncated
		}
		routes = append(routes, x.routeCall(n)...)
		if len(routes) > lim.routes {
			routes, truncated = routes[:lim.routes], true
		}
		return true
	})
	return routes, truncated || x.receiverEscapes(root)
}

// routeCall matches `recv.verb(path, ...middleware, handler)` and
// `recv.route(path).verb(...middleware, handler)`, one route per mount
// chain of the receiver. recv["verb"] counts as recv.verb (#255 tester
// M4). A key that is not a literal on a known app or router could be any
// verb, so its route matches every method and is partial, never dropped.
func (x *jsExtraction) routeCall(call *Node) []foundRoute {
	obj, verb, known, ok := x.memberKey(field(call, "function"))
	methods, isVerb := verbMethods(verb)
	if !known {
		methods, isVerb = methodsAll, true
	}
	args := jsArgs(call)
	if !ok || !isVerb || len(args) == 0 {
		return nil
	}
	base, stack := x.routeTarget(obj, args)
	if !base.ok || len(stack) == 0 || !known && base.recv == nil {
		return nil
	}
	hi := x.handlerIndex(stack)
	if !x.acceptReceiver(obj, base, stack[hi]) {
		return nil
	}
	r := foundRoute{framework: Express, methods: methods}
	if base.allAuth || x.anyAuth(stack[:hi]) {
		r.auth |= AuthMiddleware
	}
	x.addHandler(&r, stack, hi, call)
	r.facts.partial = r.facts.partial || !known
	return x.expandMounts(r, base, call.StartByte)
}

// memberKey splits a member access recv.name, or recv[key] with a literal
// key read as the runtime reads it (escapes decoded), into its object and
// name. known is false for a computed key that is not a literal; ok is
// false when fn is no member access.
func (x *jsExtraction) memberKey(fn *Node) (obj *Node, name string, known, ok bool) {
	switch {
	case fn == nil:
		return nil, "", false, false
	case fn.Type == "member_expression":
		return field(fn, "object"), x.file.text(field(fn, "property")), true, true
	case fn.Type == "subscript_expression":
		key, literal := x.file.literalString(field(fn, "index"))
		return field(fn, "object"), key, literal, true
	}
	return nil, "", false, false
}

// expandMounts emits r once per mount chain of its receiver, each with its
// own path and auth.
func (x *jsExtraction) expandMounts(r foundRoute, base routeBase, pos uint32) []foundRoute {
	local, literal := x.file.literalString(base.path)
	chains, partial := x.chainsOf(base.recv, 0)
	out := make([]foundRoute, 0, len(chains))
	for _, c := range chains {
		route := r
		prefix := chainPrefix(c)
		route.dynamic = prefix.dynamic || !literal
		if !route.dynamic {
			route.path = joinPath(prefix.path, local)
		}
		if chainAuth(base.recv, c, local, literal, pos) {
			route.auth |= AuthMiddleware
		}
		route.facts.partial = route.facts.partial || partial || chainHidden(base.recv, c)
		out = append(out, route)
	}
	return out
}

func verbMethods(verb string) (Methods, bool) {
	if verb == "all" {
		return methodsAll, true
	}
	m, ok := httpVerbs[verb]
	return m, ok
}

// routeTarget splits a verb call into its route base and its middleware and
// handler stack. On a plain receiver the first argument is the path.
func (x *jsExtraction) routeTarget(obj *Node, args []*Node) (routeBase, []*Node) {
	if obj != nil && obj.Type == "call_expression" {
		return x.chainBase(obj), flattenArgs(args)
	}
	if isFunction(unwrapCast(args[0])) {
		return routeBase{}, nil
	}
	base := routeBase{path: args[0], ok: true}
	x.setReceiver(&base, obj)
	return base, flattenArgs(args[1:])
}

func (x *jsExtraction) setReceiver(base *routeBase, obj *Node) {
	if obj != nil && obj.Type == "identifier" {
		base.name = x.file.text(obj)
		base.recv = x.receiverAt(base.name, obj.StartByte)
	}
}

// chainBase finds the app.route(path) call under a chain of verb calls,
// memoizing every link so a long chain costs linear time.
func (x *jsExtraction) chainBase(obj *Node) routeBase {
	var links []*Node
	base, found := routeBase{}, false
	for n := obj; n != nil && n.Type == "call_expression"; {
		if b, ok := x.chains[n]; ok {
			base, found = b, true
			break
		}
		obj, name, known, ok := x.memberKey(field(n, "function"))
		if !ok || !known {
			break
		}
		if name == "route" {
			base, found = x.routeOf(n, obj), true
			x.chains[n] = base
			break
		}
		if _, ok := verbMethods(name); !ok {
			break
		}
		links = append(links, n)
		n = obj
	}
	if !found {
		base = routeBase{}
	}
	for i := len(links) - 1; i >= 0; i-- {
		_, name, _, _ := x.memberKey(field(links[i], "function"))
		if base.ok && name == "all" && x.anyAuth(flattenArgs(jsArgs(links[i]))) {
			base.allAuth = true
		}
		x.chains[links[i]] = base
	}
	return base
}

func (x *jsExtraction) routeOf(call, obj *Node) routeBase {
	args := jsArgs(call)
	if len(args) != 1 {
		return routeBase{}
	}
	base := routeBase{path: args[0], ok: true}
	x.setReceiver(&base, obj)
	return base
}

// acceptReceiver keeps calls on known apps and routers. On an unknown
// receiver (a router from another file, an app passed as a parameter) the
// file must import express, the path must be a literal starting with "/" or
// "*", the receiver must be a local name, not an imported client such as
// axios, and the handler must be a function.
func (x *jsExtraction) acceptReceiver(obj *Node, base routeBase, handler *Node) bool {
	if base.recv != nil {
		return true
	}
	p, literal := x.file.literalString(base.path)
	if !x.file.express || !literal || !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "*") {
		return false
	}
	if obj != nil && obj.Type == "call_expression" {
		return true // an app.route(path) chain
	}
	_, imported := x.file.imports[base.name]
	def, _ := x.handlerDef(handler)
	return base.name != "" && !imported && def != nil
}

// anyAuth reports whether any middleware looks like an auth check.
func (x *jsExtraction) anyAuth(stack []*Node) bool {
	for _, m := range stack {
		if x.authMiddleware(m) {
			return true
		}
	}
	return false
}

// authMiddleware matches requireUser, auth.required, requireRole("admin"),
// passport.authenticate("jwt"), require("./auth") and casts of them by name.
func (x *jsExtraction) authMiddleware(n *Node) bool {
	for range maxHandlerWraps {
		n = unwrapCast(n)
		if n == nil {
			return false
		}
		if mod, ok := x.file.requireCall(n); ok {
			return authName(strings.TrimSuffix(path.Base(mod), path.Ext(mod)))
		}
		switch n.Type {
		case "identifier":
			name := x.file.text(n)
			return name != "require" && authName(name)
		case "member_expression":
			return authName(x.file.text(field(n, "property")))
		case "call_expression":
			n = field(n, "function")
		default:
			return false
		}
	}
	return false
}

// flattenArgs expands array arguments, as Express does, without recursion.
func flattenArgs(args []*Node) []*Node {
	var out []*Node
	stack := make([]*Node, 0, len(args))
	for i := len(args) - 1; i >= 0; i-- {
		stack = append(stack, args[i])
	}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n.Type != "array" {
			out = append(out, n)
			continue
		}
		c := namedChildren(n)
		for i := len(c) - 1; i >= 0; i-- {
			stack = append(stack, c[i])
		}
	}
	return out
}
