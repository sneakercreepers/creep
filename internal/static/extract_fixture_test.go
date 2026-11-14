package static

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/routes")

// summarize renders a graph with its locations, one line per route and one
// indented line per sink, for golden comparison.
func summarize(g Graph, l Locations) string {
	var b strings.Builder
	for i, f := range g.Files {
		if f.SyntaxError || f.Truncated {
			fmt.Fprintf(&b, "file %d syntax_error=%v truncated=%v\n", i, f.SyntaxError, f.Truncated)
		}
	}
	for _, r := range g.Routes {
		loc := l.Routes[r.ID]
		fmt.Fprintf(&b, "%s %s %s auth=%s params=%d dynamic=%v handler=%s:%d\n",
			r.Methods, loc.Path, r.Framework, r.Auth, r.PathParams, r.DynamicPath, loc.Handler, loc.Line)
		for _, s := range g.Sinks {
			if s.Route == r.ID {
				fmt.Fprintf(&b, "  %s %s line=%d dynamic=%v parameterized=%v indirect=%v\n",
					s.Kind, s.API, l.Sinks[s.ID].Line, s.DynamicArg, s.Parameterized, s.Indirect)
			}
		}
	}
	return b.String()
}

func extractSource(t testing.TB, src string) (Graph, Locations) {
	t.Helper()
	tree, err := testParser(t).Parse(context.Background(), Python, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	e := NewExtractor()
	if err := e.AddPython("app.py", tree, []byte(src)); err != nil {
		t.Fatal(err)
	}
	return e.Graph(), e.Locations()
}

func fixtureGraph(t *testing.T, app, variant string) (Graph, Locations) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "apps", app, variant, "app.py"))
	if err != nil {
		t.Fatal(err)
	}
	return extractSource(t, string(src))
}

// TestFixturesGolden pins the whole route/sink graph of each fixture app.
// Run `go test ./internal/static -run Golden -update` after a reviewed change.
func TestFixturesGolden(t *testing.T) {
	for _, app := range []string{"flask", "fastapi"} {
		for _, variant := range []string{"vulnerable", "safe"} {
			t.Run(app+"/"+variant, func(t *testing.T) {
				got := summarize(fixtureGraph(t, app, variant))
				golden := filepath.Join("testdata", "routes", app+"_"+variant+".golden")
				if *update {
					if err := os.WriteFile(golden, []byte(got), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(golden)
				if err != nil {
					t.Fatal(err)
				}
				if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
					t.Errorf("graph differs from %s:\n%s", golden, got)
				}
			})
		}
	}
}

type expectedApp struct {
	Vulnerable []struct {
		Class string `json:"class"`
		Line  int    `json:"line"`
		Route string `json:"route"`
	} `json:"vulnerable"`
}

// classSignal is what the static graph must show for each vulnerable class.
var classSignal = map[string]func(Route, Sink) bool{
	"sqli":           func(_ Route, s Sink) bool { return s.Kind == SinkSQL && s.DynamicArg && !s.Parameterized },
	"idor":           func(r Route, s Sink) bool { return s.Kind == SinkSQL && r.PathParams > 0 && r.Auth != 0 },
	"ssrf":           func(_ Route, s Sink) bool { return s.Kind == SinkHTTPClient && s.DynamicArg },
	"path_traversal": func(r Route, s Sink) bool { return s.Kind == SinkFile && s.DynamicArg && r.PathParams > 0 },
	"missing_auth":   func(r Route, s Sink) bool { return s.Kind == SinkSQL && r.Auth == 0 },
}

// TestFixturesMatchExpected checks every vulnerable entry in expected.json:
// its route is found, its sink is at the expected line, and the graph shows
// the signal the planner needs for that class. The safe twin must keep the
// same route and a sink of the same kind, so it is analyzed, not skipped.
func TestFixturesMatchExpected(t *testing.T) {
	for _, app := range []string{"flask", "fastapi"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "apps", app, "expected.json"))
		if err != nil {
			t.Fatal(err)
		}
		var exp expectedApp
		if err := json.Unmarshal(raw, &exp); err != nil {
			t.Fatal(err)
		}
		vg, vl := fixtureGraph(t, app, "vulnerable")
		sg, sl := fixtureGraph(t, app, "safe")
		for _, v := range exp.Vulnerable {
			t.Run(app+"/"+v.Class, func(t *testing.T) {
				r, s, ok := findSink(vg, vl, v.Route, v.Line)
				if !ok {
					t.Fatalf("no sink at line %d in route %s:\n%s", v.Line, v.Route, summarize(vg, vl))
				}
				if !classSignal[v.Class](r, s) {
					t.Errorf("route %+v sink %+v lacks the %s signal", r, s, v.Class)
				}
				if !hasSinkKind(sg, sl, v.Route, s.Kind) {
					t.Errorf("safe twin has no %s sink in %s", s.Kind, v.Route)
				}
			})
		}
	}
}

func findSink(g Graph, l Locations, path string, line int) (Route, Sink, bool) {
	for _, s := range g.Sinks {
		r := g.Routes[s.Route]
		if l.Routes[r.ID].Path == path && l.Sinks[s.ID].Line == line {
			return r, s, true
		}
	}
	return Route{}, Sink{}, false
}

func hasSinkKind(g Graph, l Locations, path string, kind SinkKind) bool {
	for _, s := range g.Sinks {
		if l.Routes[s.Route].Path == path && s.Kind == kind {
			return true
		}
	}
	return false
}
