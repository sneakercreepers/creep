package verify

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var tiers = []Tier{TierS, TierM, TierL}

// TestPromptTokenBudget fails when a tier's PoC system prompt plus the
// schema sent with it grows past its budget. Bytes bound tokens from
// above, as in models' per-call reservation.
func TestPromptTokenBudget(t *testing.T) {
	prev := 0
	for _, tier := range tiers {
		system, err := System(tier)
		if err != nil {
			t.Fatal(err)
		}
		budget, ok := promptBudget[tier]
		if !ok {
			t.Fatalf("tier %s has no budget", tier)
		}
		used := len(system) + len(Schema())
		if used > budget || used < prev {
			t.Errorf("tier %s takes %d tokens, budget %d, smaller tier %d", tier, used, budget, prev)
		}
		prev = used
		for _, name := range []string{TemplateHTTPRequest, TemplateHTTPSequence, TemplateSQLPayload, TemplatePathPayload, NoncePlaceholder, PayloadPlaceholder} {
			if !strings.Contains(system, name) {
				t.Errorf("tier %s prompt does not name %s", tier, name)
			}
		}
	}
	if len(promptBudget) != len(tiers) {
		t.Errorf("promptBudget has %d tiers, want %d", len(promptBudget), len(tiers))
	}
	if _, err := System("XL"); !errors.Is(err, ErrTier) {
		t.Errorf("System(XL): %v", err)
	}
}

// TestSchemaIsClosed: the schema is a JSON object; every object in it
// closes additionalProperties and requires each of its properties, as
// strict mode needs, and every header name it lists is one Validate
// allows. Every golden fixture uses only keys the schema names.
func TestSchemaIsClosed(t *testing.T) {
	var root map[string]any
	if err := json.Unmarshal(Schema(), &root); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	walkSchema(t, root, keys)
	files, err := filepath.Glob(filepath.Join("testdata", "golden", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatal(files, err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatal(err)
		}
		for _, k := range objectKeys(v) {
			if !keys[k] {
				t.Errorf("%s: key %q is not in the schema", f, k)
			}
		}
	}
}

func walkSchema(t *testing.T, node any, keys map[string]bool) {
	t.Helper()
	switch n := node.(type) {
	case []any:
		for _, c := range n {
			walkSchema(t, c, keys)
		}
	case map[string]any:
		if props, ok := n["properties"].(map[string]any); ok {
			checkObject(t, n, props)
			for k := range props {
				keys[k] = true
			}
		}
		if names, ok := n["enum"].([]any); ok && slices.Contains(names, any("User-Agent")) {
			for _, h := range names {
				if !slices.Contains(allowedHeaders, h.(string)) {
					t.Errorf("schema header %v is not allowed", h)
				}
			}
		}
		for _, c := range n {
			walkSchema(t, c, keys)
		}
	}
}

func checkObject(t *testing.T, n, props map[string]any) {
	t.Helper()
	if n["additionalProperties"] != false {
		t.Errorf("object %v is not closed", slices.Sorted(maps.Keys(props)))
	}
	required, _ := n["required"].([]any)
	if len(required) != len(props) {
		t.Errorf("object %v requires %v", slices.Sorted(maps.Keys(props)), required)
	}
}

func objectKeys(v any) []string {
	var out []string
	switch n := v.(type) {
	case []any:
		for _, c := range n {
			out = append(out, objectKeys(c)...)
		}
	case map[string]any:
		for k, c := range n {
			out = append(out, k)
			out = append(out, objectKeys(c)...)
		}
	}
	return out
}

// TestTemplatesFitTheirClass: each class gets only templates whose oracle
// proves it, a class with no template gets no prompt, and the prompt
// names the allowed templates and holds the code as given.
func TestTemplatesFitTheirClass(t *testing.T) {
	sqlPoC := mustBuild(t, loadRequest(t, "sql_payload_marker"))
	pathPoC := mustBuild(t, loadRequest(t, "path_payload_relative"))
	reflectPoC := mustBuild(t, loadRequest(t, "http_request_reflect"))
	tests := []struct {
		class string
		fits  []PoC
		not   []PoC
	}{
		{"sqli", []PoC{sqlPoC}, []PoC{pathPoC, reflectPoC}},
		{"path_traversal", []PoC{pathPoC}, []PoC{sqlPoC, reflectPoC}},
		{"template_injection", []PoC{reflectPoC}, []PoC{sqlPoC, pathPoC}},
		{"command_injection", nil, []PoC{sqlPoC, pathPoC, reflectPoC}},
		{"ssrf", nil, []PoC{reflectPoC}},
	}
	for _, tt := range tests {
		for _, p := range tt.fits {
			if !Fits(tt.class, p) {
				t.Errorf("%s: %s does not fit", tt.class, p.Template())
			}
		}
		for _, p := range tt.not {
			if Fits(tt.class, p) {
				t.Errorf("%s: %s fits", tt.class, p.Template())
			}
		}
		prompt, err := UserPrompt(tt.class, "1 code")
		if (err != nil) != (len(tt.fits) == 0) {
			t.Errorf("%s: prompt error %v", tt.class, err)
		}
		if err == nil && (!strings.HasSuffix(prompt, "\n\n1 code") || !strings.Contains(prompt, strings.Join(TemplatesFor(tt.class), ", "))) {
			t.Errorf("%s: prompt %q", tt.class, prompt)
		}
	}
}
