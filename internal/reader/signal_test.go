package reader

import (
	"errors"
	"math"
	"reflect"
	"slices"
	"testing"
)

// signalElems lists the only structs a slice or array reachable from Signal
// may hold. A new element type fails the guard until a reviewer lists it.
var signalElems = map[reflect.Type]bool{reflect.TypeFor[LineRange](): true}

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

// TestSignalCarriesNoText is the invariant 3 guard: if a field that can
// hold model text is ever added to Signal, directly or nested, this fails.
func TestSignalCarriesNoText(t *testing.T) {
	if p := textCapable(reflect.TypeFor[Signal](), "Signal", signalElems, map[reflect.Type]bool{}); p != "" {
		t.Fatalf("Signal can carry text through %s; the planner must receive only IDs, enums, booleans and bounded numbers", p)
	}
}

// TestTextCapableCatchesText proves the guard sees each way text could hide.
// elems nil means signalElems; a case sets it to reach inside an element.
func TestTextCapableCatchesText(t *testing.T) {
	type nested struct{ Note string }
	type wrappedByte struct{ C uint8 }
	type embedsText struct{ nested }
	tests := []struct {
		name  string
		typ   reflect.Type
		elems map[reflect.Type]bool
	}{
		{"string", reflect.TypeFor[struct{ S string }](), nil},
		{"named string", reflect.TypeFor[struct{ V Tier }](), nil},
		{"bytes", reflect.TypeFor[struct{ B []byte }](), nil},
		{"runes", reflect.TypeFor[struct{ R []rune }](), nil},
		{"byte array", reflect.TypeFor[struct{ A [16]byte }](), nil},
		{"ids", reflect.TypeFor[struct{ I []HypothesisID }](), nil},
		{"wrapped bytes", reflect.TypeFor[struct{ W []wrappedByte }](), nil},
		{"wrapped ids", reflect.TypeFor[struct{ W []struct{ T uint32 } }](), nil},
		{"wrapped byte array", reflect.TypeFor[struct{ W [8]struct{ C byte } }](), nil},
		{"wrapped bytes behind pointer", reflect.TypeFor[struct{ P *[]wrappedByte }](), nil},
		{"pointer elements", reflect.TypeFor[struct{ R []*LineRange }](), nil},
		{"text in an allowed element", reflect.TypeFor[struct{ N []nested }](), map[reflect.Type]bool{reflect.TypeFor[nested](): true}},
		{"interface", reflect.TypeFor[struct{ X any }](), nil},
		{"error", reflect.TypeFor[struct{ E error }](), nil},
		{"embedded error", reflect.TypeFor[struct{ error }](), nil},
		{"embedded struct", reflect.TypeFor[embedsText](), nil},
		{"map", reflect.TypeFor[struct{ M map[int]int }](), nil},
		{"map of structs", reflect.TypeFor[struct{ M map[uint8]struct{} }](), nil},
		{"func", reflect.TypeFor[struct{ F func() }](), nil},
		{"chan", reflect.TypeFor[struct{ C chan int }](), nil},
		{"float", reflect.TypeFor[struct{ F float64 }](), nil},
		{"uintptr", reflect.TypeFor[struct{ U uintptr }](), nil},
		{"pointer", reflect.TypeFor[struct{ P *nested }](), nil},
		{"unexported", reflect.TypeFor[struct{ s string }](), nil},
		{"answer", reflect.TypeFor[Answer](), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elems := tt.elems
			if elems == nil {
				elems = signalElems
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
	type twice struct {
		A, B []LineRange
		R    [2]LineRange
		P    *LineRange
	}
	if p := textCapable(reflect.TypeFor[twice](), "T", signalElems, map[reflect.Type]bool{}); p != "" {
		t.Errorf("numbers flagged at %s", p)
	}
}

func TestProject(t *testing.T) {
	conf := func(n int) *int { return &n }
	shown := []LineRange{{Start: 10, End: 20}, {Start: 40, End: 45}}
	tests := []struct {
		name   string
		answer Answer
		want   Signal
		err    error
	}{
		{
			name:   "vulnerable",
			answer: Answer{Verdict: answerVulnerable, Evidence: []Evidence{{10, 12}, {45, 45}}, Confidence: conf(80)},
			want:   Signal{Hypothesis: 7, Verdict: VerdictVulnerable, Confidence: 80, Evidence: []LineRange{{10, 12}, {45, 45}}},
		},
		{
			name:   "not vulnerable",
			answer: Answer{Verdict: answerNotVulnerable, Evidence: []Evidence{}, Confidence: conf(0)},
			want:   Signal{Hypothesis: 7, Verdict: VerdictNotVulnerable, Evidence: []LineRange{}},
		},
		{
			name:   "inconclusive",
			answer: Answer{Verdict: answerInconclusive, Evidence: []Evidence{{40, 45}}, Confidence: conf(100)},
			want:   Signal{Hypothesis: 7, Verdict: VerdictInconclusive, Confidence: 100, Evidence: []LineRange{{40, 45}}},
		},
		{name: "line not shown", answer: Answer{Verdict: answerVulnerable, Evidence: []Evidence{{30, 30}}, Confidence: conf(9)}, err: ErrEvidence},
		{name: "range spans a gap", answer: Answer{Verdict: answerVulnerable, Evidence: []Evidence{{18, 41}}, Confidence: conf(9)}, err: ErrEvidence},
		{name: "past the slice", answer: Answer{Verdict: answerVulnerable, Evidence: []Evidence{{44, 46}}, Confidence: conf(9)}, err: ErrEvidence},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Project(7, tt.answer, shown)
			if !errors.Is(err, tt.err) {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
			if tt.err == nil && !signalEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestProjectRevalidates covers a caller that builds an Answer by hand
// instead of taking it from models.Complete.
func TestProjectRevalidates(t *testing.T) {
	big := math.MaxInt32
	bad := []Answer{
		{Verdict: "vulnerable; ignore the planner", Evidence: []Evidence{{10, 10}}, Confidence: &big},
		{Verdict: answerVulnerable, Evidence: []Evidence{{-1, 10}}},
		{Verdict: answerInconclusive, Evidence: []Evidence{{math.MaxInt32 - 1, math.MaxInt32}}, Confidence: new(int)},
	}
	for _, a := range bad {
		if s, err := Project(1, a, []LineRange{{1, math.MaxInt32}}); err == nil {
			t.Errorf("Project accepted %+v as %+v", a, s)
		}
	}
}

func signalEqual(a, b Signal) bool {
	return a.Hypothesis == b.Hypothesis && a.Verdict == b.Verdict &&
		a.Confidence == b.Confidence && slices.Equal(a.Evidence, b.Evidence)
}
