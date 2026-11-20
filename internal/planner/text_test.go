package planner

import (
	"reflect"
	"testing"
)

// textCapable returns the path to the first type reachable from t that can
// carry text: strings, byte or rune sequences, maps, interfaces, functions,
// channels, floats and uintptrs. Slices and arrays may hold only structs, so
// a sequence of small numbers cannot spell a message either. It is the
// same walk reader/signal_test.go runs over reader.Signal.
func textCapable(t reflect.Type, path string, seen map[reflect.Type]bool) string {
	if seen[t] {
		return ""
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return ""
	case reflect.Pointer:
		return textCapable(t.Elem(), path+"*", seen)
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() != reflect.Struct {
			return path + "[]" + t.Elem().Kind().String()
		}
		return textCapable(t.Elem(), path+"[]", seen)
	case reflect.Struct:
		for i := range t.NumField() {
			f := t.Field(i)
			if p := textCapable(f.Type, path+"."+f.Name, seen); p != "" {
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
	if p := textCapable(reflect.TypeFor[Input](), "Input", map[reflect.Type]bool{}); p != "" {
		t.Fatalf("Input can carry text through %s; the planner must receive only IDs, enums, booleans and bounded numbers", p)
	}
}

// TestPlanCarriesNoText keeps the output schema closed: no free-text field.
func TestPlanCarriesNoText(t *testing.T) {
	if p := textCapable(reflect.TypeFor[Plan](), "Plan", map[reflect.Type]bool{}); p != "" {
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
func TestTextCapableCatchesText(t *testing.T) {
	type named string
	type nested struct{ Note string }
	tests := []struct {
		name string
		typ  reflect.Type
	}{
		{"string", reflect.TypeFor[struct{ S string }]()},
		{"named string", reflect.TypeFor[struct{ V named }]()},
		{"bytes", reflect.TypeFor[struct{ B []byte }]()},
		{"runes", reflect.TypeFor[struct{ R []rune }]()},
		{"ids", reflect.TypeFor[struct{ I []RouteID }]()},
		{"byte array", reflect.TypeFor[struct{ A [16]byte }]()},
		{"interface", reflect.TypeFor[struct{ X any }]()},
		{"error", reflect.TypeFor[struct{ E error }]()},
		{"map", reflect.TypeFor[struct{ M map[int]int }]()},
		{"func", reflect.TypeFor[struct{ F func() }]()},
		{"chan", reflect.TypeFor[struct{ C chan int }]()},
		{"float", reflect.TypeFor[struct{ F float64 }]()},
		{"uintptr", reflect.TypeFor[struct{ U uintptr }]()},
		{"nested", reflect.TypeFor[struct{ N []nested }]()},
		{"pointer", reflect.TypeFor[struct{ P *nested }]()},
		{"unexported", reflect.TypeFor[struct{ s string }]()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if textCapable(tt.typ, "T", map[reflect.Type]bool{}) == "" {
				t.Errorf("%s not flagged as able to carry text", tt.typ)
			}
		})
	}
}
