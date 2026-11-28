package report

import (
	"path/filepath"
	"slices"
	"testing"
)

// TestSchemaListsEverySkipReason ties the schema's not-evaluated reason
// enum to skipReasons, so a reason added to one (vendor_exceeds_read,
// #380) cannot be missing from the other.
func TestSchemaListsEverySkipReason(t *testing.T) {
	schema := loadJSON(t, filepath.Join("..", "..", "docs", "schemas", "report-v1.json"))
	var enum []string
	reason := dig(t, schema, "definitions", "notEvaluated", "properties", "reason", "enum")
	values, ok := reason.([]any)
	if !ok {
		t.Fatalf("reason enum is %T, want an array", reason)
	}
	for _, v := range values {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("reason enum value %v is not a string", v)
		}
		enum = append(enum, s)
	}
	var want []string
	for r := range skipReasons {
		want = append(want, string(r))
	}
	slices.Sort(enum)
	slices.Sort(want)
	if !slices.Equal(enum, want) {
		t.Errorf("schema reasons %v, skipReasons %v", enum, want)
	}
}

func dig(t *testing.T, v any, keys ...string) any {
	t.Helper()
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("at %q: %T is not an object", k, v)
		}
		v = m[k]
	}
	return v
}
