package static

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// markerPrefix starts every planted marker; nothing creep emits contains it.
const markerPrefix = "QZVMK"

// edit replaces src[start:end] with text.
type edit struct {
	start, end uint32
	text       string
}

// plantMarkers returns src with a unique marker in every text position that
// does not change what extraction detects: the end of each string and
// comment, and a suffix on every name the file defines (functions, classes,
// parameters, variables), renamed consistently. Imported names, attribute
// names and keyword names stay, as do HTTP method strings, so the graph
// keeps its shape and the test proves only that the text stays out.
func plantMarkers(t *testing.T, src []byte) []byte {
	t.Helper()
	tree, err := testParser(t).Parse(context.Background(), Python, src)
	if err != nil {
		t.Fatal(err)
	}
	f := newPyFile(tree.Root, src)
	defined := definedNames(f, tree.Root)
	var edits []edit
	n := 0
	mark := func() string { n++; return fmt.Sprintf("%s%04d", markerPrefix, n) }
	keywords := map[*Node]bool{}
	walk(tree.Root, func(c *Node) bool {
		switch {
		case c.Type == "keyword_argument":
			keywords[field(c, "name")] = true
		case c.Type == "string_content" && methodFromName(f.text(c)) == MethodOther:
			edits = append(edits, edit{c.EndByte, c.EndByte, mark()})
		case c.Type == "comment":
			edits = append(edits, edit{c.EndByte, c.EndByte, " " + mark()})
		case c.Type == "identifier" && c.Field != "attribute" && !keywords[c] && defined[f.text(c)]:
			edits = append(edits, edit{c.StartByte, c.EndByte, f.text(c) + "_" + markerPrefix + f.text(c)})
		}
		return true
	})
	if len(edits) < 20 {
		t.Fatalf("only %d positions marked", len(edits))
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	out := append([]byte(nil), src...)
	for _, e := range edits {
		out = append(out[:e.start:e.start], append([]byte(e.text), out[e.end:]...)...)
	}
	return out
}

// definedNames lists names bound in the file other than by import, minus
// keyword-argument names, which must keep matching the callee.
func definedNames(f *pyFile, root *Node) map[string]bool {
	names := map[string]bool{}
	walk(root, func(n *Node) bool {
		switch n.Type {
		case "function_definition", "class_definition":
			names[f.text(field(n, "name"))] = true
		case "assignment", "for_statement", "for_in_clause":
			if l := field(n, "left"); l != nil && l.Type == "identifier" {
				names[f.text(l)] = true
			}
		case "parameters":
			for _, p := range namedChildren(n) {
				if p.Type == "identifier" {
					names[f.text(p)] = true
				} else if id := field(p, "name"); id != nil {
					names[f.text(id)] = true
				} else if c := namedChildren(p); len(c) > 0 && c[0].Type == "identifier" {
					names[f.text(c[0])] = true
				}
			}
		}
		return true
	})
	for local := range f.imports {
		delete(names, local)
	}
	delete(names, "")
	return names
}

// planned renders every planner-facing form of a graph: JSON, Go syntax and
// the enum names a prompt would use.
func planned(t *testing.T, g Graph) string {
	t.Helper()
	js, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%+v\n%#v\n", js, g, g)
	for _, r := range g.Routes {
		fmt.Fprintln(&b, r.Framework, r.Methods, r.Auth)
	}
	for _, s := range g.Sinks {
		fmt.Fprintln(&b, s.Kind, s.API)
	}
	for _, f := range g.Files {
		fmt.Fprintln(&b, f.Language, f.Ignored)
	}
	return b.String()
}

// TestPlannerOutputHasNoRepoStrings is the end-to-end proof for invariant 3
// over testdata/apps: every fixture, with markers planted in every text
// position and in its path, yields the same graph as the original, its
// locations carry the markers, and no planner-facing form of the graph
// contains any of them.
func TestPlannerOutputHasNoRepoStrings(t *testing.T) {
	for _, app := range []string{"flask", "fastapi"} {
		for _, variant := range []string{"vulnerable", "safe"} {
			t.Run(app+"/"+variant, func(t *testing.T) {
				src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "apps", app, variant, "app.py"))
				if err != nil {
					t.Fatal(err)
				}
				want, _ := extractSource(t, string(src))
				marked := plantMarkers(t, src)
				tree, err := testParser(t).Parse(context.Background(), Python, marked)
				if err != nil {
					t.Fatal(err)
				}
				e := NewExtractor()
				if err := e.AddPython(markerPrefix+"dir/"+markerPrefix+"app.py", tree, marked); err != nil {
					t.Fatal(err)
				}
				got := e.Graph()
				if len(got.Routes) == 0 || !reflect.DeepEqual(got, want) {
					t.Fatalf("markers changed the graph:\n%s\nwant:\n%s", planned(t, got), planned(t, want))
				}
				if out := planned(t, got); strings.Contains(strings.ToUpper(out), markerPrefix) {
					t.Errorf("planner-facing graph carries repository text:\n%s", out)
				}
				assertLocationsMarked(t, e.Locations())
			})
		}
	}
}

// assertLocationsMarked proves the markers reached the extractor: the report
// side still sees them.
func assertLocationsMarked(t *testing.T, l Locations) {
	t.Helper()
	locs, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{markerPrefix + "dir/", `"Handler":"`} {
		if !strings.Contains(string(locs), want) {
			t.Errorf("locations lack %q: %s", want, locs)
		}
	}
	for _, r := range l.Routes {
		// An anonymous Express handler has no name to mark.
		if (r.Handler != "" && !strings.Contains(r.Handler, markerPrefix)) || (r.Path != "" && !strings.Contains(r.Path, markerPrefix)) {
			t.Errorf("route location not marked: %+v", r)
		}
	}
}
