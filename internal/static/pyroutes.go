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
}

// pyRoute is a route before it gets IDs.
type pyRoute struct {
	framework Framework
	methods   Methods
	path      string
	dynamic   bool
	auth      AuthVia
	handler   string
	line      int
	facts     handlerFacts
}

// extractPython returns the routes in one file, at most maxRoutes; truncated
// is set when more were declared.
func extractPython(root *Node, src []byte, maxRoutes int) (routes []pyRoute, truncated bool) {
	x := &pyExtraction{
		file:      newPyFile(root, src),
		receivers: map[string]*receiver{},
		authVars:  map[string]bool{},
		handlers:  map[*Node]handlerFacts{},
		helpers:   map[*Node][]foundSink{},
		scans:     map[*Node]bodyScan{},
		prefixes:  map[string]mountPrefix{},
	}
	x.collectReceivers(root)
	walk(root, func(n *Node) bool {
		if truncated || n.Type != "decorated_definition" {
			return !truncated
		}
		routes = append(routes, x.decorated(n)...)
		if len(routes) > maxRoutes {
			routes, truncated = routes[:maxRoutes], true
		}
		return true
	})
	return routes, truncated
}

// decorated returns one route per route decorator on a function.
func (x *pyExtraction) decorated(n *Node) []pyRoute {
	def := field(n, "definition")
	if def == nil || def.Type != "function_definition" {
		return nil
	}
	var routes []pyRoute
	var auth AuthVia
	for _, d := range n.Children {
		if d.Type != "decorator" || len(namedChildren(d)) == 0 {
			continue
		}
		expr := namedChildren(d)[0]
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
	for i := range routes {
		r := &routes[i]
		r.auth |= auth
		if r.framework == FastAPI && x.paramsAuth(def) {
			r.auth |= AuthDependency
		}
		r.handler, r.line, r.facts = handler, line(def), facts
	}
	return routes
}

// routeDecorator matches `@recv.route(...)`, `@recv.get(...)` and the like.
func (x *pyExtraction) routeDecorator(expr *Node) (pyRoute, bool) {
	fn := field(expr, "function")
	if expr.Type != "call" || fn == nil || fn.Type != "attribute" {
		return pyRoute{}, false
	}
	verb := x.file.text(field(fn, "attribute"))
	obj := field(fn, "object")
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
	if !ok {
		return pyRoute{}, false
	}
	pos, kw := callArgs(expr)
	pathNode := firstOf(pos, keyword(x.file, kw, "rule", "path"))
	if pathNode == nil {
		return pyRoute{}, false
	}
	r := pyRoute{framework: fw, methods: methods}
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
