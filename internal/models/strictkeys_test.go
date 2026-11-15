package models

import (
	"strings"
	"testing"
)

type strictInner struct {
	Line int `json:"line"`
}

type strictOutput struct {
	Verdict string                 `json:"verdict"`
	Items   []strictInner          `json:"items"`
	One     *strictInner           `json:"one"`
	Labels  map[string]strictInner `json:"labels"`
	Plain   int                    // no tag: exact Go name only
	Skipped int                    `json:"-"`
}

// TestDecodeOutputStrictKeys covers what encoding/json alone lets through:
// duplicate keys (last wins) and keys matched without regard to case.
func TestDecodeOutputStrictKeys(t *testing.T) {
	tests := []struct {
		name, content, want string
	}{
		{"valid", `{"verdict":"a","items":[{"line":1}],"one":{"line":2},"labels":{"x":{"line":3},"X":{"line":4}},"Plain":1}`, ""},
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
