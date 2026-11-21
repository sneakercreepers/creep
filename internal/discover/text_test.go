package discover

import (
	"reflect"
	"testing"
)

// resultElems lists the only structs a slice or array reachable from
// Result may hold. A new element type fails the guard until a reviewer
// lists it.
var resultElems = map[reflect.Type]bool{
	reflect.TypeFor[File]():     true,
	reflect.TypeFor[Route]():    true,
	reflect.TypeFor[Sink]():     true,
	reflect.TypeFor[AuthSpan](): true,
}

// textCapable returns the path to the first type reachable from t that can
// carry text: strings, byte or rune sequences, maps, interfaces, functions,
// channels, floats and uintptrs. A slice or array may hold only a struct
// listed in elems, because a sequence of small numbers, or of structs that
// wrap them, can spell a message byte by byte. planner/text_test.go holds
// the same function; TestTextGuardsMatch there fails if the two drift.
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

// TestResultCarriesNoText is the invariant 3 guard on the new path: the
// value that fills planner.Input and reader.Target can hold only IDs,
// enums, line numbers and booleans.
func TestResultCarriesNoText(t *testing.T) {
	if p := textCapable(reflect.TypeFor[Result](), "Result", resultElems, map[reflect.Type]bool{}); p != "" {
		t.Fatalf("Result can carry text through %s; discovery output must hold only IDs and enums", p)
	}
}

// TestTextCapableCatchesText proves the guard sees each way text could hide.
func TestTextCapableCatchesText(t *testing.T) {
	type named string
	type wrappedByte struct{ C byte }
	tests := []reflect.Type{
		reflect.TypeFor[struct{ S string }](),
		reflect.TypeFor[struct{ V named }](),
		reflect.TypeFor[struct{ B []byte }](),
		reflect.TypeFor[struct{ I []SinkID }](),
		reflect.TypeFor[struct{ A [16]byte }](),
		reflect.TypeFor[struct{ W []wrappedByte }](),
		reflect.TypeFor[struct{ W []struct{ L uint32 } }](),
		reflect.TypeFor[struct{ P *[]wrappedByte }](),
		reflect.TypeFor[struct{ X any }](),
		reflect.TypeFor[struct{ E error }](),
		reflect.TypeFor[struct{ error }](),
		reflect.TypeFor[struct{ M map[int]int }](),
		reflect.TypeFor[struct{ F func() }](),
		reflect.TypeFor[struct{ F float64 }](),
		reflect.TypeFor[struct{ N []struct{ Note string } }](),
		reflect.TypeFor[struct{ s string }](),
	}
	for _, typ := range tests {
		if textCapable(typ, "T", resultElems, map[reflect.Type]bool{}) == "" {
			t.Errorf("%s not flagged as able to carry text", typ)
		}
	}
}
