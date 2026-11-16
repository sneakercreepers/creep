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
	file      *jsFile
	receivers map[string]*jsReceiver
	chains    map[*Node]routeBase
	handlers  map[*Node]handlerFacts
	helpers   map[*Node][]foundSink
	scans     map[*Node]*jsScan
	prefixes  map[string]mountPrefix
	// constBudget bounds DynamicArg analysis and scanBudget bounds handler
	// scans (jsbind.go).
	constBudget, scanBudget int
}

// routeBase is the receiver and path of an app.route(path) chain.
type routeBase struct {
	recv    string
	path    *Node
	allAuth bool // an earlier .all(...) link in the chain holds auth middleware
	ok      bool
}

func extractJavaScript(root *Node, src []byte, lim extractLimits) (routes []foundRoute, truncated bool) {
	x := &jsExtraction{
		file:        newJSFile(root, src),
		receivers:   map[string]*jsReceiver{},
		chains:      map[*Node]routeBase{},
		handlers:    map[*Node]handlerFacts{},
		helpers:     map[*Node][]foundSink{},
		scans:       map[*Node]*jsScan{},
		prefixes:    map[string]mountPrefix{},
		constBudget: lim.constVisits,
		scanBudget:  lim.scanVisits,
	}
	x.collectReceivers(root)
	walk(root, func(n *Node) bool {
		if truncated || n.Type != "call_expression" {
			return !truncated
		}
		if r, ok := x.routeCall(n); ok {
			routes = append(routes, r)
		}
		if len(routes) > lim.routes {
			routes, truncated = routes[:lim.routes], true
		}
		return true
	})
	return routes, truncated
}

// routeCall matches `recv.verb(path, ...middleware, handler)` and
// `recv.route(path).verb(...middleware, handler)`.
func (x *jsExtraction) routeCall(call *Node) (foundRoute, bool) {
	fn := field(call, "function")
	if fn == nil || fn.Type != "member_expression" {
		return foundRoute{}, false
	}
	methods, ok := x.verbMethods(fn)
	args := jsArgs(call)
	if !ok || len(args) == 0 {
		return foundRoute{}, false
	}
	base, stack := x.routeTarget(field(fn, "object"), args)
	if !base.ok || len(stack) == 0 || !x.acceptReceiver(field(fn, "object"), base, stack) {
		return foundRoute{}, false
	}
	r := foundRoute{framework: Express, methods: methods}
	p, literal := x.file.literalString(base.path)
	prefix := x.prefix(base.recv)
	r.dynamic = prefix.dynamic || !literal
	if !r.dynamic {
		r.path = joinPath(prefix.path, p)
	}
	if base.allAuth || x.anyAuth(stack[:len(stack)-1]) || x.receiverAuth(base.recv, p, literal, call.StartByte) {
		r.auth |= AuthMiddleware
	}
	x.addHandler(&r, stack[len(stack)-1], call)
	return r, true
}

func (x *jsExtraction) verbMethods(fn *Node) (Methods, bool) {
	verb := x.file.text(field(fn, "property"))
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
	if isFunction(args[0]) {
		return routeBase{}, nil
	}
	base := routeBase{path: args[0], ok: true}
	if obj != nil && obj.Type == "identifier" {
		base.recv = x.file.text(obj)
	}
	return base, flattenArgs(args[1:])
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
		fn := field(n, "function")
		if fn == nil || fn.Type != "member_expression" {
			break
		}
		if x.file.text(field(fn, "property")) == "route" {
			base, found = x.routeOf(n, fn), true
			x.chains[n] = base
			break
		}
		if _, ok := x.verbMethods(fn); !ok {
			break
		}
		links = append(links, n)
		n = field(fn, "object")
	}
	if !found {
		base = routeBase{}
	}
	for i := len(links) - 1; i >= 0; i-- {
		fn := field(links[i], "function")
		if base.ok && x.file.text(field(fn, "property")) == "all" && x.anyAuth(flattenArgs(jsArgs(links[i]))) {
			base.allAuth = true
		}
		x.chains[links[i]] = base
	}
	return base
}

func (x *jsExtraction) routeOf(call, fn *Node) routeBase {
	args := jsArgs(call)
	if len(args) != 1 {
		return routeBase{}
	}
	base := routeBase{path: args[0], ok: true}
	if obj := field(fn, "object"); obj != nil && obj.Type == "identifier" {
		base.recv = x.file.text(obj)
	}
	return base
}

// acceptReceiver keeps calls on known apps and routers. On an unknown
// receiver (a router from another file, an app passed as a parameter) the
// file must import express, the path must be a literal starting with "/" or
// "*", the receiver must be a local name, not an imported client such as
// axios, and the handler must be a function.
func (x *jsExtraction) acceptReceiver(obj *Node, base routeBase, stack []*Node) bool {
	if x.receivers[base.recv] != nil {
		return true
	}
	p, literal := x.file.literalString(base.path)
	if !x.file.express || !literal || !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "*") {
		return false
	}
	if obj != nil && obj.Type == "call_expression" {
		return true // an app.route(path) chain
	}
	recv := base.recv
	_, imported := x.file.imports[recv]
	def, _ := x.handlerDef(stack[len(stack)-1])
	return recv != "" && !imported && def != nil
}

// addHandler sets the route's handler name, line and facts.
func (x *jsExtraction) addHandler(r *foundRoute, handler, call *Node) {
	def, name := x.handlerDef(handler)
	r.handler, r.line = capText(name, maxHandlerBytes), line(call)
	if def == nil {
		return
	}
	r.line, r.facts = line(def), x.facts(def)
	if r.facts.authCall {
		r.auth |= AuthCall
	}
}

// handlerDef resolves a handler expression to a function in the file:
// a function literal, a top-level function name, or either wrapped in calls
// such as asyncHandler(fn). name is "" for an anonymous function.
func (x *jsExtraction) handlerDef(n *Node) (def *Node, name string) {
	for range maxHandlerWraps {
		switch {
		case n == nil:
			return nil, ""
		case isFunction(n):
			return n, x.file.text(field(n, "name"))
		case n.Type == "identifier":
			return x.file.funcs[x.file.text(n)], x.file.text(n)
		case n.Type == "call_expression":
			args := jsArgs(n)
			if len(args) == 0 {
				return nil, ""
			}
			n = args[len(args)-1]
		default:
			return nil, x.file.text(n)
		}
	}
	return nil, ""
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
// passport.authenticate("jwt") and require("./auth") by name.
func (x *jsExtraction) authMiddleware(n *Node) bool {
	for range maxHandlerWraps {
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
