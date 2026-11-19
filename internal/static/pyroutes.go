package static

import "strings"

// Bounds on repository text kept per route, so a hostile file with a huge
// prefix or name mounted many times cannot multiply memory.
const (
	maxPathBytes    = 2048
	maxHandlerBytes = 256
	// maxMountDepth bounds blueprint and router nesting, which also ends
	// mount cycles.
	maxMountDepth = 16
)

// appConstructors are the calls that create something routes hang off.
var appConstructors = map[string]Framework{
	"flask.Flask":                Flask,
	"flask.Blueprint":            Flask,
	"flask.blueprints.Blueprint": Flask,
	"fastapi.FastAPI":            FastAPI,
	"fastapi.APIRouter":          FastAPI,
	"fastapi.routing.APIRouter":  FastAPI,
}

var httpVerbs = map[string]Methods{
	"get": MethodGet, "post": MethodPost, "put": MethodPut, "patch": MethodPatch,
	"delete": MethodDelete, "head": MethodHead, "options": MethodOptions, "trace": MethodTrace,
}

// pyExtraction is the state of extracting routes from one Python file.
type pyExtraction struct {
	file      *pyFile
	receivers map[string]*receiver
	authVars  map[string]bool // variables bound to fastapi.security schemes
	handlers  map[*Node]handlerFacts
	helpers   map[*Node][]foundSink
	scans     map[*Node]bodyScan
	prefixes  map[string]mountPrefix
	// constBudget bounds DynamicArg analysis (pybind.go).
	constBudget int // nodes DynamicArg analysis may still visit
}

// extractPython returns the routes in one file, at most lim.routes; truncated
// is set when more were declared.
func extractPython(root *Node, src []byte, lim extractLimits) (routes []foundRoute, truncated bool) {
	x := &pyExtraction{
		file:        newPyFile(root, src),
		receivers:   map[string]*receiver{},
		authVars:    map[string]bool{},
		handlers:    map[*Node]handlerFacts{},
		helpers:     map[*Node][]foundSink{},
		scans:       map[*Node]bodyScan{},
		prefixes:    map[string]mountPrefix{},
		constBudget: lim.constVisits,
	}
	x.collectReceivers(root)
	walk(root, func(n *Node) bool {
		if truncated || n.Type != "decorated_definition" {
			return !truncated
		}
		routes = append(routes, x.decorated(n)...)
		if len(routes) > lim.routes {
			routes, truncated = routes[:lim.routes], true
		}
		return true
	})
	return routes, truncated || x.receiverEscapes(root, len(routes) > 0)
}

// decorated returns one route per route decorator on a function.
func (x *pyExtraction) decorated(n *Node) []foundRoute {
	def := field(n, "definition")
	if def == nil || def.Type != "function_definition" {
		return nil
	}
	var routes []foundRoute
	var auth AuthVia
	for _, d := range n.Children {
		if d.Type != "decorator" || len(namedChildren(d)) == 0 {
			continue
		}
		expr := unwrapParens(namedChildren(d)[0]) // @(app.route(p)), Python 3.9+
		if r, ok := x.routeDecorator(expr); ok {
			routes = append(routes, r)
			continue
		}
		if authName(x.calleeName(expr)) {
			auth |= AuthDecorator
		}
	}
	if len(routes) == 0 {
		return nil
	}
	facts := x.facts(def)
	if facts.authCall {
		auth |= AuthCall
	}
	handler := capText(x.file.text(field(def, "name")), maxHandlerBytes)
	paramsAuth := x.paramsAuth(def) // once per def, not per decorator
	for i := range routes {
		r := &routes[i]
		r.auth |= auth
		if r.framework == FastAPI && paramsAuth {
			r.auth |= AuthDependency
		}
		partial := r.facts.partial
		r.handler, r.line, r.facts = handler, line(def), facts
		r.facts.partial = r.facts.partial || partial
	}
	return routes
}

// routeDecorator matches `@recv.route(...)`, `@recv.get(...)` and the
// like, also spelled `@getattr(recv, "route")(...)`. A getattr name that
// is not a literal, on a known app or router, could be any verb: its route
// matches every method and is partial, never dropped.
func (x *pyExtraction) routeDecorator(expr *Node) (foundRoute, bool) {
	if expr.Type != "call" {
		return foundRoute{}, false
	}
	obj, verb, known, ok := x.attrKey(field(expr, "function"))
	if !ok {
		return foundRoute{}, false
	}
	recvName := ""
	if obj != nil && obj.Type == "identifier" {
		recvName = x.file.text(obj)
	}
	recv := x.receivers[recvName]
	fw := x.guessFramework(verb)
	if recv != nil {
		fw = recv.framework
	}
	methods, ok := x.routeMethods(fw, verb, expr)
	if !known {
		methods, ok = methodsAll, recv != nil
	}
	if !ok {
		return foundRoute{}, false
	}
	pos, kw := callArgs(expr)
	pathNode := firstOf(pos, keyword(x.file, kw, "rule", "path"))
	if pathNode == nil {
		return foundRoute{}, false
	}
	r := foundRoute{framework: fw, methods: methods}
	r.facts.partial = !known
	if x.depsAuth(keyword(x.file, kw, "dependencies")) {
		r.auth |= AuthDependency
	}
	var prefix mountPrefix
	if recv != nil {
		prefix = x.prefix(recvName)
	}
	path, literal := x.file.literalString(pathNode)
	r.dynamic = prefix.dynamic || !literal
	if prefix.auth {
		r.auth |= AuthDependency
	}
	if !r.dynamic {
		r.path = joinPath(prefix.path, path)
	}
	return r, true
}

// guessFramework handles decorators on receivers defined in another file:
// .route is Flask; HTTP verbs follow the framework the file imports.
func (x *pyExtraction) guessFramework(verb string) Framework {
	switch {
	case verb == "route":
		return Flask
	case verb == "api_route":
		return FastAPI
	case httpVerbs[verb] == 0:
		return 0
	case x.file.fastapi:
		return FastAPI
	case x.file.flask:
		return Flask
	}
	return 0
}

func (x *pyExtraction) routeMethods(fw Framework, verb string, call *Node) (Methods, bool) {
	if m := httpVerbs[verb]; m != 0 && fw != 0 {
		if fw == Flask && m&(MethodGet|MethodPost|MethodPut|MethodPatch|MethodDelete) == 0 {
			return 0, false
		}
		return m, true
	}
	if (fw == Flask && verb == "route") || (fw == FastAPI && verb == "api_route") {
		_, kw := callArgs(call)
		return x.methodList(keyword(x.file, kw, "methods")), true
	}
	return 0, false
}

// methodList reads methods=[...]; a missing list means GET, anything not a
// literal list of known methods adds MethodOther.
func (x *pyExtraction) methodList(n *Node) Methods {
	if n == nil {
		return MethodGet
	}
	if n.Type != "list" && n.Type != "tuple" && n.Type != "set" {
		return MethodOther
	}
	var m Methods
	for _, c := range namedChildren(n) {
		name, ok := x.file.literalString(c)
		if !ok {
			m |= MethodOther
			continue
		}
		m |= methodFromName(name)
	}
	if m == 0 {
		return MethodOther
	}
	return m
}

// calleeName resolves a decorator or call target, unwrapping `@deco(...)`.
func (x *pyExtraction) calleeName(expr *Node) string {
	if expr.Type == "call" {
		expr = field(expr, "function")
	}
	name, _ := x.file.resolve(expr)
	return name
}

func firstOf(pos []*Node, alt *Node) *Node {
	if len(pos) > 0 {
		return pos[0]
	}
	return alt
}

// joinPath concatenates route path parts, capped at maxPathBytes.
func joinPath(a, b string) string {
	if len(a) >= maxPathBytes {
		return a[:maxPathBytes]
	}
	return capText(a+capText(b, maxPathBytes), maxPathBytes)
}

func capText(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func lastSegment(name string) string {
	return name[strings.LastIndexByte(name, '.')+1:]
}
