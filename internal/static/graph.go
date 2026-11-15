package static

import "strings"

// Graph is the planner-facing result of route extraction. It holds only IDs,
// enums, booleans and counts, never text from the scanned repository: paths,
// handler names and file names live in Locations, which only the report reads.
// TestGraphHoldsNoStrings keeps it that way.
type Graph struct {
	Files  []File
	Routes []Route
	Sinks  []Sink
}

// FileID, RouteID and SinkID index Graph.Files, Graph.Routes and Graph.Sinks
// and the matching slices in Locations.
type (
	FileID  uint32
	RouteID uint32
	SinkID  uint32
)

// File is one extracted source file.
type File struct {
	ID       FileID
	Language Language
	// SyntaxError is set when the tree has ERROR or MISSING nodes, so routes
	// inside the broken region may be missing.
	SyntaxError bool
	// Truncated is set when the file hit a route or sink cap; the scan of
	// that file is incomplete.
	Truncated bool
}

// Route is one HTTP endpoint and the handler that serves it.
type Route struct {
	ID        RouteID
	File      FileID
	Framework Framework
	Methods   Methods
	// PathParams counts path parameters such as <int:id> or {item_id}.
	PathParams int
	// DynamicPath is set when the path or a mount prefix is not a string
	// literal, so the full path is unknown.
	DynamicPath bool
	Auth        AuthVia
	// Partial is set when the route's sinks were cut at a cap or their
	// analysis ran out of budget; File.Truncated is set too.
	Partial bool
}

// Sink is a dangerous call reachable from a route handler.
type Sink struct {
	ID    SinkID
	Route RouteID
	Kind  SinkKind
	API   SinkAPI
	// DynamicArg is set when the first argument is not built only from
	// string literals (an f-string, concatenation, call or unknown name).
	DynamicArg bool
	// Parameterized is set when a SQL call passes bound parameters.
	Parameterized bool
	// Indirect is set when the call sits in a same-file helper that the
	// handler calls, not in the handler itself.
	Indirect bool
}

// Locations maps graph IDs back to repository text for the report. It must
// never reach the planner.
type Locations struct {
	Files  []string // slash-separated path as given to AddPython
	Routes []RouteLocation
	Sinks  []SinkLocation
}

// RouteLocation is where a route is declared.
type RouteLocation struct {
	// Path is the full route path with known prefixes, or "" when the path
	// is dynamic.
	Path    string
	Handler string
	Line    int // 1-based line of the handler's def
}

// SinkLocation is where a sink call is.
type SinkLocation struct {
	Line int // 1-based
}

// Framework is the web framework that declared a route.
type Framework uint8

// Frameworks. The zero value is not a framework.
const (
	Flask Framework = iota + 1
	FastAPI
)

// String returns the framework name.
func (f Framework) String() string {
	switch f {
	case Flask:
		return "flask"
	case FastAPI:
		return "fastapi"
	}
	return "unknown"
}

// Methods is a set of HTTP methods.
type Methods uint16

// HTTP methods. MethodOther stands for a method list that is not literal or
// names a method outside this set.
const (
	MethodGet Methods = 1 << iota
	MethodPost
	MethodPut
	MethodPatch
	MethodDelete
	MethodHead
	MethodOptions
	MethodTrace
	MethodOther
)

var methodNames = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "OTHER"}

// methodFromName maps a case-insensitive method name to its bit.
func methodFromName(name string) Methods {
	for i, m := range methodNames[:len(methodNames)-1] {
		if strings.EqualFold(name, m) {
			return 1 << i
		}
	}
	return MethodOther
}

// String joins the set with "|", for example "GET|POST".
func (m Methods) String() string {
	var names []string
	for i, name := range methodNames {
		if m&(1<<i) != 0 {
			names = append(names, name)
		}
	}
	return strings.Join(names, "|")
}

// AuthVia is the set of ways a route was seen to require authentication.
// Detection is by name (login_required, Depends(require_admin), a
// current_user() call), so it is a hint for the planner, not proof.
type AuthVia uint8

// Ways a route can require authentication.
const (
	// AuthDecorator: a decorator on the handler.
	AuthDecorator AuthVia = 1 << iota
	// AuthDependency: a FastAPI Depends or Security on the route, its
	// parameters, or a router or app it is mounted on.
	AuthDependency
	// AuthCall: the handler body calls an auth-named function.
	AuthCall
)

// String joins the set with "|", or returns "none".
func (a AuthVia) String() string {
	var names []string
	for i, name := range []string{"decorator", "dependency", "call"} {
		if a&(1<<i) != 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, "|")
}

// SinkKind is the class of a dangerous call.
type SinkKind uint8

// Sink kinds. The zero value is not a kind.
const (
	SinkSQL SinkKind = iota + 1
	SinkShell
	SinkFile
	SinkHTTPClient
	SinkTemplate
)

// String returns the kind name.
func (k SinkKind) String() string {
	switch k {
	case SinkSQL:
		return "sql"
	case SinkShell:
		return "shell"
	case SinkFile:
		return "file"
	case SinkHTTPClient:
		return "http_client"
	case SinkTemplate:
		return "template"
	}
	return "unknown"
}
