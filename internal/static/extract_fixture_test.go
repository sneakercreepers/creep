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
		partial := ""
		if r.Partial {
			partial = " partial=true"
		}
		fmt.Fprintf(&b, "%s %s %s auth=%s params=%d dynamic=%v handler=%s:%d%s\n",
			r.Methods, loc.Path, r.Framework, r.Auth, r.PathParams, r.DynamicPath, loc.Handler, loc.Line, partial)
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
	return extractFile(t, "app.py", []byte(src))
}

// extractFile parses src with the grammar its name picks and extracts it.
func extractFile(t testing.TB, name string, src []byte) (Graph, Locations) {
	t.Helper()
	e := NewExtractor()
	if err := addFile(t, e, name, src); err != nil {
		t.Fatal(err)
	}
	return e.Graph(), e.Locations()
}

func addFile(t testing.TB, e *Extractor, name string, src []byte) error {
	t.Helper()
	lang, ok := LanguageForPath(name)
	if !ok {
		t.Fatalf("no grammar for %s", name)
	}
	tree, err := testParser(t).Parse(context.Background(), lang, src)
	if err != nil {
		t.Fatal(err)
	}
	if lang == Python {
		return e.AddPython(name, tree, src)
	}
	return e.AddJavaScript(name, tree, src)
}

// fixtureApps are the testdata/apps fixtures and their entry file.
var fixtureApps = []struct{ app, file string }{
	{"flask", "app.py"}, {"fastapi", "app.py"}, {"express", "app.js"},
}

// fixtureFiles lists every fixture source with the golden name it pins:
// both variants of each testdata/apps fixture, plus the TypeScript Express
// fixture in testdata/express.
func fixtureFiles() []struct{ golden, path string } {
	var out []struct{ golden, path string }
	for _, a := range fixtureApps {
		for _, variant := range []string{"vulnerable", "safe"} {
			out = append(out, struct{ golden, path string }{
				a.app + "_" + variant, filepath.Join("..", "..", "testdata", "apps", a.app, variant, a.file),
			})
		}
	}
	return append(out, struct{ golden, path string }{"express_ts", filepath.Join("testdata", "express", "app.ts")})
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func fixtureGraph(t *testing.T, app, file, variant string) (Graph, Locations) {
	t.Helper()
	return extractFile(t, file, readFixture(t, filepath.Join("..", "..", "testdata", "apps", app, variant, file)))
}

// TestFixturesGolden pins the whole route/sink graph of each fixture app.
// Run `go test ./internal/static -run Golden -update` after a reviewed change.
func TestFixturesGolden(t *testing.T) {
	for _, f := range fixtureFiles() {
		t.Run(f.golden, func(t *testing.T) {
			got := summarize(extractFile(t, filepath.Base(f.path), readFixture(t, f.path)))
			golden := filepath.Join("testdata", "routes", f.golden+".golden")
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

type expectedApp struct {
	Vulnerable []struct {
		Class string `json:"class"`
		Line  int    `json:"line"`
		Route string `json:"route"`
	} `json:"vulnerable"`
}

// classSignal is what the static graph must show for each vulnerable class.
var classSignal = map[string]func(Route, Sink) bool{
	"sqli": func(_ Route, s Sink) bool { return s.Kind == SinkSQL && s.DynamicArg && !s.Parameterized },
	"idor": func(r Route, s Sink) bool {
		return (s.Kind == SinkSQL || s.Kind == SinkNoSQL) && r.PathParams > 0 && r.Auth != 0
	},
	"ssrf":              func(_ Route, s Sink) bool { return s.Kind == SinkHTTPClient && s.DynamicArg },
	"path_traversal":    func(r Route, s Sink) bool { return s.Kind == SinkFile && s.DynamicArg && r.PathParams > 0 },
	"missing_auth":      func(r Route, s Sink) bool { return s.Kind == SinkSQL && r.Auth == 0 },
	"nosql_injection":   func(_ Route, s Sink) bool { return s.Kind == SinkNoSQL && s.DynamicArg },
	"command_injection": func(_ Route, s Sink) bool { return s.Kind == SinkShell && s.DynamicArg },
}

// routeOnlyClasses have no call sink in the graph's taxonomy: prototype
// pollution is a computed-key write inside a helper, not a call. The graph
// must still list their route so the planner can pick it.
var routeOnlyClasses = map[string]bool{"prototype_pollution": true}

// TestFixturesMatchExpected checks every vulnerable entry in expected.json:
// its route is found, its sink is at the expected line, and the graph shows
// the signal the planner needs for that class. The safe twin must keep the
// same route and a sink of the same kind, so it is analyzed, not skipped.
func TestFixturesMatchExpected(t *testing.T) {
	for _, a := range fixtureApps {
		var exp expectedApp
		if err := json.Unmarshal(readFixture(t, filepath.Join("..", "..", "testdata", "apps", a.app, "expected.json")), &exp); err != nil {
			t.Fatal(err)
		}
		vg, vl := fixtureGraph(t, a.app, a.file, "vulnerable")
		sg, sl := fixtureGraph(t, a.app, a.file, "safe")
		for _, v := range exp.Vulnerable {
			t.Run(a.app+"/"+v.Class, func(t *testing.T) {
				if routeOnlyClasses[v.Class] {
					if !hasRoute(vl, v.Route) || !hasRoute(sl, v.Route) {
						t.Fatalf("route %s missing:\n%s", v.Route, summarize(vg, vl))
					}
					return
				}
				r, s, ok := findSink(vg, vl, v.Route, v.Line)
				if !ok {
					t.Fatalf("no sink at line %d in route %s:\n%s", v.Line, v.Route, summarize(vg, vl))
				}
				if signal, known := classSignal[v.Class]; !known || !signal(r, s) {
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

func hasRoute(l Locations, path string) bool {
	for _, r := range l.Routes {
		if r.Path == path {
			return true
		}
	}
	return false
}
