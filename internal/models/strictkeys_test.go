package models

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type strictInner struct {
	Line int `json:"line"`
}

// strictOpen decodes itself, so strictKeys may check only its duplicates.
type strictOpen struct{ keys map[string]any }

func (o *strictOpen) UnmarshalJSON(b []byte) error { return json.Unmarshal(b, &o.keys) }

type strictOutput struct {
	strictInner                        // embedded: its "line" is promoted
	Verdict     string                 `json:"verdict"`
	Items       []strictInner          `json:"items"`
	One         *strictInner           `json:"one"`
	Labels      map[string]strictInner `json:"labels"`
	Open        strictOpen             `json:"open"`
	Plain       int                    // no tag: exact Go name only
	Skipped     int                    `json:"-"`
	Dash        int                    `json:"-,"` //nolint:staticcheck // SA5008: the "-," name is the strictkeys branch under test
}

// TestDecodeOutputStrictKeys covers what encoding/json alone lets through:
// duplicate keys (last wins) and keys matched without regard to case.
func TestDecodeOutputStrictKeys(t *testing.T) {
	tests := []struct {
		name, content, want string
	}{
		{"valid", `{"line":5,"verdict":"a","items":[{"line":1}],"one":{"line":2},"labels":{"x":{"line":3},"X":{"line":4}},"open":{"k":1,"K":2},"Plain":1,"-":1}`, ""},
		{"promoted case variant", `{"Line":1}`, reasonKeyCase},
		{"promoted duplicate", `{"line":1,"line":2}`, reasonDuplicateKey},
		{"unmarshaler allows any case", `{"open":{"Verdict":1,"VERDICT":{"x":1}}}`, ""},
		{"unmarshaler refuses duplicates", `{"open":{"k":1,"k":2}}`, reasonDuplicateKey},
		{"unmarshaler refuses nested duplicates", `{"open":{"k":{"a":1,"a":2}}}`, reasonDuplicateKey},
		{"dash name duplicate", `{"-":1,"-":2}`, reasonDuplicateKey},
		{"dash field Go name", `{"Dash":1}`, "it had a field the schema does not allow"},
		{"skipped field", `{"Skipped":1}`, "it had a field the schema does not allow"},
		{"duplicate top key", `{"verdict":"a","verdict":"b"}`, reasonDuplicateKey},
		{"case variant", `{"Verdict":"a"}`, reasonKeyCase},
		{"case variant beside exact", `{"verdict":"a","VERDICT":"b"}`, reasonKeyCase},
		{"untagged lowercase", `{"plain":1}`, reasonKeyCase},
		{"duplicate in array item", `{"items":[{"line":1},{"line":2,"line":3}]}`, reasonDuplicateKey},
		{"case variant in array item", `{"items":[{"Line":1}]}`, reasonKeyCase},
		{"duplicate in pointer", `{"one":{"line":1,"line":2}}`, reasonDuplicateKey},
		{"duplicate map key", `{"labels":{"x":{"line":1},"x":{"line":2}}}`, reasonDuplicateKey},
		{"case variant in map value", `{"labels":{"x":{"LINE":1}}}`, reasonKeyCase},
		{"escaped duplicate", `{"verdict":"a","verdict":"b"}`, reasonDuplicateKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := decodeOutput[strictOutput]([]byte(tt.content))
			if got != tt.want {
				t.Errorf("reason = %q, want %q", got, tt.want)
			}
		})
	}
}

type strictShadowed struct {
	X string `json:"x"`
}

// encoding/json decodes "x" into the shallow int; strictKeys must not
// check it against the deeper string, whatever the field order.
type (
	strictShadowAfter struct {
		X int `json:"x"`
		strictShadowed
	}
	strictShadowBefore struct {
		strictShadowed
		X int `json:"x"`
	}
	strictShadowPointer struct {
		*strictShadowed
		Y int `json:"x"`
	}
	strictShadowNested struct {
		In strictShadowAfter `json:"in"`
	}
)

// TestStrictKeysRefusesAmbiguousTypes covers promoted fields that share a
// JSON name: the type is refused, so a future output type cannot be checked
// against the wrong field without anyone noticing.
func TestStrictKeysRefusesAmbiguousTypes(t *testing.T) {
	tests := []struct {
		name, content, want string
		typ                 reflect.Type
	}{
		{"deeper field after", `{"x":1}`, reasonAmbiguous, reflect.TypeFor[strictShadowAfter]()},
		{"deeper field before", `{"x":1}`, reasonAmbiguous, reflect.TypeFor[strictShadowBefore]()},
		{"embedded pointer", `{"x":1}`, reasonAmbiguous, reflect.TypeFor[strictShadowPointer]()},
		{"empty object", `{}`, reasonAmbiguous, reflect.TypeFor[strictShadowAfter]()},
		{"nested object", `{"in":{}}`, reasonAmbiguous, reflect.TypeFor[strictShadowNested]()},
		{"nested object absent", `{}`, "", reflect.TypeFor[strictShadowNested]()},
		{"no conflict", `{"x":"a"}`, "", reflect.TypeFor[strictShadowed]()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strictKeys([]byte(tt.content), tt.typ); got != tt.want {
				t.Errorf("reason = %q, want %q", got, tt.want)
			}
		})
	}
	if _, got := decodeOutput[strictShadowBefore]([]byte(`{"x":1}`)); got != reasonAmbiguous {
		t.Errorf("decodeOutput reason = %q, want %q", got, reasonAmbiguous)
	}
}

// TestStrictKeysDeepNesting checks open values (any, raw JSON) deep inside
// a reply: any key is allowed there, but a duplicate is still refused.
func TestStrictKeysDeepNesting(t *testing.T) {
	const depth = 9000 // under encoding/json's own nesting limit
	nested := `{"v":` + strings.Repeat(`{"a":`, depth) + `1` + strings.Repeat("}", depth) + `}`
	if got := strictKeys([]byte(nested), nil); got != "" {
		t.Errorf("deep valid object rejected: %q", got)
	}
	dup := `{"v":` + strings.Repeat(`{"a":`, depth) + `{"b":1,"b":2}` + strings.Repeat("}", depth) + `}`
	if got := strictKeys([]byte(dup), nil); got != reasonDuplicateKey {
		t.Errorf("deep duplicate = %q, want %q", got, reasonDuplicateKey)
	}
}
