package static

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// maxFileRoutes caps the routes kept per file; File.Truncated marks the rest.
const maxFileRoutes = 4096

// ErrGraphFull means the graph ran out of 32-bit IDs.
var ErrGraphFull = errors.New("route graph full")

// extractLimits are the per-file caps; tests lower them.
type extractLimits struct {
	routes      int // routes kept per file
	constVisits int // node visits for DynamicArg analysis per file
}

// Extractor builds one Graph from many parsed files. IDs are assigned in the
// order files and routes are added, so the same input gives the same graph.
// It is not safe for concurrent use.
type Extractor struct {
	graph Graph
	locs  Locations
	lim   extractLimits
}

// NewExtractor returns an empty Extractor.
func NewExtractor() *Extractor {
	return &Extractor{lim: extractLimits{routes: maxFileRoutes, constVisits: maxConstVisits}}
}

// AddPython extracts Flask and FastAPI routes, their sinks and auth from a
// Python tree that Parser.Parse built from src. path is relative to the
// repository root (see IgnoreReason) and kept only in Locations. Each file is parsed once by the caller and passed here. A file
// that IgnoreReason rejects is listed as ignored instead of extracted, so a
// caller that skips the check still never reads vendor or generated code.
func (e *Extractor) AddPython(path string, tree *Tree, src []byte) error {
	switch {
	case tree == nil || tree.Root == nil:
		return fmt.Errorf("extract %s: no tree", path)
	case tree.Language != Python:
		return fmt.Errorf("extract %s: %s tree is not python", path, tree.Language)
	case int(tree.Root.EndByte) > len(src):
		return fmt.Errorf("extract %s: tree does not match source", path)
	}
	why, err := IgnoreReason(path, src)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	if why != 0 {
		return e.AddIgnored(path, why)
	}
	routes, truncated := extractPython(tree.Root, src, e.lim)
	sinks := 0
	for _, r := range routes {
		sinks += len(r.facts.sinks)
		truncated = truncated || r.facts.truncated || r.facts.partial
	}
	if !fits(len(e.graph.Files)+1) || !fits(len(e.graph.Routes)+len(routes)) || !fits(len(e.graph.Sinks)+sinks) {
		return fmt.Errorf("extract %s: %w", path, ErrGraphFull)
	}
	file := FileID(len(e.graph.Files)) //nolint:gosec // G115: fits checked above
	e.graph.Files = append(e.graph.Files, File{ID: file, Language: Python, SyntaxError: tree.HasError, Truncated: truncated})
	e.locs.Files = append(e.locs.Files, path)
	for _, r := range routes {
		e.addRoute(file, r)
	}
	return nil
}

func (e *Extractor) addRoute(file FileID, r pyRoute) {
	id := RouteID(len(e.graph.Routes)) //nolint:gosec // G115: fits checked by AddPython
	e.graph.Routes = append(e.graph.Routes, Route{
		ID: id, File: file, Framework: r.framework, Methods: r.methods,
		PathParams: pathParams(r.framework, r.path), DynamicPath: r.dynamic, Auth: r.auth,
		Partial: r.facts.truncated || r.facts.partial,
	})
	e.locs.Routes = append(e.locs.Routes, RouteLocation{Path: r.path, Handler: r.handler, Line: r.line})
	for _, s := range r.facts.sinks {
		e.graph.Sinks = append(e.graph.Sinks, Sink{
			ID: SinkID(len(e.graph.Sinks)), Route: id, Kind: s.api.Kind(), API: s.api, //nolint:gosec // G115: fits checked by AddPython
			DynamicArg: s.dynamic, Parameterized: s.parameterized, Indirect: s.ind,
		})
		e.locs.Sinks = append(e.locs.Sinks, SinkLocation{Line: s.line})
	}
}

// Graph returns the planner-facing graph. The slices are shared with the
// Extractor; do not add files after handing them out.
func (e *Extractor) Graph() Graph { return e.graph }

// Locations returns the report-only text for each ID.
func (e *Extractor) Locations() Locations { return e.locs }

// pathParams counts <converter:name> (Flask) or {name} (FastAPI) segments.
func pathParams(fw Framework, path string) int {
	if fw == Flask {
		return strings.Count(path, "<")
	}
	return strings.Count(path, "{")
}

func fits(n int) bool { return n <= math.MaxUint32 }
