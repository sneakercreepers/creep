package planner

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"reflect"
	"testing"
)

// plannerElems lists the only structs a slice or array reachable from
// Input or Plan may hold. A new element type fails the guard until a
// reviewer lists it.
var plannerElems = map[reflect.Type]bool{
	reflect.TypeFor[Route]():      true,
	reflect.TypeFor[Sink]():       true,
	reflect.TypeFor[Hypothesis](): true,
	reflect.TypeFor[Skipped]():    true,
}

// textCapable returns the path to the first type reachable from t that can
// carry text: strings, byte or rune sequences, maps, interfaces, functions,
// channels, floats and uintptrs. A slice or array may hold only a struct
// listed in elems, because a sequence of small numbers, or of structs that
// wrap them, can spell a message byte by byte. discover/text_test.go and
// reader/signal_test.go hold the same function; TestTextGuardsMatch fails
// if they drift.
func textCapable(t reflect.Type, path string, elems, seen map[reflect.Type]bool) string {
	if seen[t] {
		return ""
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return ""
	case reflect.Pointer:
		return textCapable(t.Elem(), path+"*", elems, seen)
	case reflect.Slice, reflect.Array:
		if !elems[t.Elem()] {
			return path + "[]" + t.Elem().String() + " (element type not allowed)"
		}
		return textCapable(t.Elem(), path+"[]", elems, seen)
	case reflect.Struct:
		for i := range t.NumField() {
			f := t.Field(i)
			if p := textCapable(f.Type, path+"."+f.Name, elems, seen); p != "" {
				return p
			}
		}
		return ""
	}
	return path + " (" + t.Kind().String() + ")"
}

// TestInputCarriesNoText is the invariant 3 guard: if a field that can
// hold repository text is ever added to Input, directly or nested, this
// fails.
func TestInputCarriesNoText(t *testing.T) {
	if p := textCapable(reflect.TypeFor[Input](), "Input", plannerElems, map[reflect.Type]bool{}); p != "" {
		t.Fatalf("Input can carry text through %s; the planner must receive only IDs, enums, booleans and bounded numbers", p)
	}
}

// TestPlanCarriesNoText keeps the output schema closed: no free-text field.
func TestPlanCarriesNoText(t *testing.T) {
	if p := textCapable(reflect.TypeFor[Plan](), "Plan", plannerElems, map[reflect.Type]bool{}); p != "" {
		t.Fatalf("Plan can carry text through %s; the output must hold only IDs and enums", p)
	}
}

// TestBuildTakesOnlyInput fails if Build grows a parameter, such as an
// option string or a context carrying values, that could bring text in
// beside Input.
func TestBuildTakesOnlyInput(t *testing.T) {
	ft := reflect.TypeOf(Build)
	if ft.NumIn() != 1 || ft.In(0) != reflect.TypeFor[Input]() {
		t.Fatalf("Build has signature %s; it must take only planner.Input", ft)
	}
}

// TestTextCapableCatchesText proves the guard sees each way text could hide.
// elems nil means plannerElems; a case sets it to reach inside an element.
func TestTextCapableCatchesText(t *testing.T) {
	type named string
	type nested struct{ Note string }
	type wrappedByte struct{ C byte }
	type embedsText struct{ nested }
	tests := []struct {
		name  string
		typ   reflect.Type
		elems map[reflect.Type]bool
	}{
		{"string", reflect.TypeFor[struct{ S string }](), nil},
		{"named string", reflect.TypeFor[struct{ V named }](), nil},
		{"bytes", reflect.TypeFor[struct{ B []byte }](), nil},
		{"runes", reflect.TypeFor[struct{ R []rune }](), nil},
		{"ids", reflect.TypeFor[struct{ I []RouteID }](), nil},
		{"byte array", reflect.TypeFor[struct{ A [16]byte }](), nil},
		{"wrapped bytes", reflect.TypeFor[struct{ W []wrappedByte }](), nil},
		{"wrapped ids", reflect.TypeFor[struct{ W []struct{ T uint32 } }](), nil},
		{"wrapped route ids", reflect.TypeFor[struct{ W []struct{ R RouteID } }](), nil},
		{"wrapped byte array", reflect.TypeFor[struct{ W [8]struct{ C byte } }](), nil},
		{"wrapped bytes behind pointer", reflect.TypeFor[struct{ P *[]wrappedByte }](), nil},
		{"pointer elements", reflect.TypeFor[struct{ R []*Route }](), nil},
		{"text in an allowed element", reflect.TypeFor[struct{ N []nested }](), map[reflect.Type]bool{reflect.TypeFor[nested](): true}},
		{"interface", reflect.TypeFor[struct{ X any }](), nil},
		{"error", reflect.TypeFor[struct{ E error }](), nil},
		{"embedded error", reflect.TypeFor[struct{ error }](), nil},
		{"embedded struct", reflect.TypeFor[embedsText](), nil},
		{"map", reflect.TypeFor[struct{ M map[int]int }](), nil},
		{"map of structs", reflect.TypeFor[struct{ M map[SinkID]struct{} }](), nil},
		{"func", reflect.TypeFor[struct{ F func() }](), nil},
		{"chan", reflect.TypeFor[struct{ C chan int }](), nil},
		{"float", reflect.TypeFor[struct{ F float64 }](), nil},
		{"uintptr", reflect.TypeFor[struct{ U uintptr }](), nil},
		{"pointer", reflect.TypeFor[struct{ P *nested }](), nil},
		{"unexported", reflect.TypeFor[struct{ s string }](), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elems := tt.elems
			if elems == nil {
				elems = plannerElems
			}
			if textCapable(tt.typ, "T", elems, map[reflect.Type]bool{}) == "" {
				t.Errorf("%s not flagged as able to carry text", tt.typ)
			}
		})
	}
}

// TestTextCapableAllowsNumbers keeps the guard from passing by flagging
// everything: listed elements and bounded numbers go through.
func TestTextCapableAllowsNumbers(t *testing.T) {
	type both struct {
		In  Input
		Out Plan
		R   [2]Route
		P   *Sink
	}
	if p := textCapable(reflect.TypeFor[both](), "T", plannerElems, map[reflect.Type]bool{}); p != "" {
		t.Errorf("numbers flagged at %s", p)
	}
}

// TestTextGuardsMatch fails when this walk and the discover or reader copy
// differ, so a fix to one guard cannot leave another behind. The packages
// may not import each other, so they cannot share one function.
func TestTextGuardsMatch(t *testing.T) {
	here := funcSource(t, "text_test.go", "textCapable")
	for _, file := range []string{"../discover/text_test.go", "../reader/signal_test.go"} {
		if there := funcSource(t, file, "textCapable"); there != here {
			t.Errorf("textCapable in %s differs from planner's:\n%s\n--- planner ---\n%s", file, there, here)
		}
	}
}

// funcSource returns the printed declaration of function name in file.
func funcSource(t *testing.T, file, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		var b bytes.Buffer
		if err := printer.Fprint(&b, fset, fn); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	t.Fatalf("%s: no func %s", file, name)
	return ""
}
