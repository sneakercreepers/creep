package discover

import (
	"reflect"
	"testing"
)

// textCapable returns the path to the first type reachable from t that can
// carry text: strings, byte or rune sequences, maps, interfaces, functions,
// channels, floats and uintptrs. Slices and arrays may hold only structs.
// It is the walk planner/text_test.go runs over planner.Input.
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

// TestResultCarriesNoText is the invariant 3 guard on the new path: the
// value that fills planner.Input and reader.Target can hold only IDs,
// enums, line numbers and booleans.
func TestResultCarriesNoText(t *testing.T) {
	if p := textCapable(reflect.TypeFor[Result](), "Result", map[reflect.Type]bool{}); p != "" {
		t.Fatalf("Result can carry text through %s; discovery output must hold only IDs and enums", p)
	}
}

// TestTextCapableCatchesText proves the guard sees each way text could hide.
func TestTextCapableCatchesText(t *testing.T) {
	type named string
	tests := []reflect.Type{
		reflect.TypeFor[struct{ S string }](),
		reflect.TypeFor[struct{ V named }](),
		reflect.TypeFor[struct{ B []byte }](),
		reflect.TypeFor[struct{ I []SinkID }](),
		reflect.TypeFor[struct{ A [16]byte }](),
		reflect.TypeFor[struct{ X any }](),
		reflect.TypeFor[struct{ E error }](),
		reflect.TypeFor[struct{ M map[int]int }](),
		reflect.TypeFor[struct{ F func() }](),
		reflect.TypeFor[struct{ F float64 }](),
		reflect.TypeFor[struct{ N []struct{ Note string } }](),
		reflect.TypeFor[struct{ s string }](),
	}
	for _, typ := range tests {
		if textCapable(typ, "T", map[reflect.Type]bool{}) == "" {
			t.Errorf("%s not flagged as able to carry text", typ)
		}
	}
}
