package static

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// plantJSMarkers is plantMarkers for JavaScript and TypeScript: a unique
// marker at the end of every string and template fragment and inside every
// comment, and a suffix on every name the file defines (variables,
// functions, parameters), renamed consistently. Module specifiers and the
// paths of use() and all() calls stay, so imports resolve and path-scoped
// guards keep covering the same routes; the graph keeps its shape and the
// test proves only that the text stays out.
func plantJSMarkers(t *testing.T, lang Language, src []byte) []byte {
	t.Helper()
	tree, err := testParser(t).Parse(context.Background(), lang, src)
	if err != nil {
		t.Fatal(err)
	}
	f := newJSFile(tree.Root, src)
	defined, kept := jsDefinedNames(f, tree.Root), keptStrings(f, tree.Root)
	var edits []edit
	n := 0
	mark := func() string { n++; return fmt.Sprintf("%s%04d", markerPrefix, n) }
	walk(tree.Root, func(c *Node) bool {
		text := f.text(c)
		switch {
		case kept[c]:
			return false
		case c.Type == "string_fragment":
			edits = append(edits, edit{c.EndByte, c.EndByte, mark()})
		case c.Type == "comment" && strings.HasPrefix(text, "/*"):
			edits = append(edits, edit{c.EndByte - 2, c.EndByte - 2, " " + mark() + " "})
		case c.Type == "comment":
			edits = append(edits, edit{c.EndByte, c.EndByte, " " + mark()})
		case c.Type == "identifier" && defined[text]:
			edits = append(edits, edit{c.StartByte, c.EndByte, text + "_" + markerPrefix + text})
		case c.Type == "shorthand_property_identifier" && defined[text]:
			edits = append(edits, edit{c.StartByte, c.EndByte, text + ": " + text + "_" + markerPrefix + text})
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

// jsDefinedNames lists names bound by declarators, function declarations
// and parameters, minus imports, which must keep resolving to modules.
func jsDefinedNames(f *jsFile, root *Node) map[string]bool {
	names := map[string]bool{}
	add := func(n *Node) {
		if n != nil && n.Type == "identifier" {
			names[f.text(n)] = true
		}
	}
	walk(root, func(n *Node) bool {
		switch n.Type {
		case "variable_declarator", "function_declaration":
			add(field(n, "name"))
		case "arrow_function":
			add(field(n, "parameter"))
		case "formal_parameters":
			for _, p := range namedChildren(n) {
				add(p)
				add(field(p, "pattern"))
			}
		}
		return true
	})
	for local := range f.imports {
		delete(names, local)
	}
	return names
}

// keptStrings are module specifiers and use()/all() path arguments.
func keptStrings(f *jsFile, root *Node) map[*Node]bool {
	kept := map[*Node]bool{}
	walk(root, func(n *Node) bool {
		switch n.Type {
		case "import_statement", "import_require_clause":
			kept[field(n, "source")] = true
		case "call_expression":
			fn := field(n, "function")
			name := f.text(fn)
			if fn != nil && fn.Type == "member_expression" {
				name = f.text(field(fn, "property"))
			}
			if name == "require" || name == "use" || name == "all" {
				for _, a := range jsArgs(n) {
					kept[a] = a.Type == "string"
				}
			}
		}
		return true
	})
	return kept
}

// TestPlannerOutputHasNoRepoStringsJS is TestPlannerOutputHasNoRepoStrings
// for the Express fixtures, JavaScript and TypeScript.
func TestPlannerOutputHasNoRepoStringsJS(t *testing.T) {
	for _, f := range fixtureFiles() {
		lang, _ := LanguageForPath(f.path)
		if lang == Python {
			continue
		}
		t.Run(f.golden, func(t *testing.T) {
			src := readFixture(t, f.path)
			want, _ := extractFile(t, filepath.Base(f.path), src)
			marked := plantJSMarkers(t, lang, src)
			e := NewExtractor()
			if err := addFile(t, e, markerPrefix+"dir/"+markerPrefix+filepath.Base(f.path), marked); err != nil {
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
