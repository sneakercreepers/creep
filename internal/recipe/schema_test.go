package recipe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/sneakercreepers/creep/internal/reader"
)

// schemaPath is the published recipe schema. The binary never reads it:
// these tests keep it in sync with the Go decoder, which is the authority.
var schemaPath = filepath.Join("..", "..", "docs", "schemas", "recipe-v1.json")

type schemaDoc map[string]any

func loadSchema(t *testing.T) schemaDoc {
	t.Helper()
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var s schemaDoc
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSchemaMatchesRecipe keeps the published schema describing what Parse
// accepts: the same closed objects, required keys, class enum and limits.
func TestSchemaMatchesRecipe(t *testing.T) {
	s := loadSchema(t)
	defs := s.obj("definitions")
	fixtures := s.obj("properties").obj("fixtures")
	for _, tt := range []struct {
		name     string
		schema   schemaDoc
		typ      reflect.Type
		optional []string
	}{
		{"recipe", s, reflect.TypeFor[Recipe](), []string{"poc"}},
		{"fixtures", fixtures, reflect.TypeFor[Fixtures](), nil},
		{"fixture", defs.obj("fixture"), reflect.TypeFor[Fixture](), nil},
	} {
		tags := jsonTags(tt.typ)
		if got := sortedKeys(tt.schema.obj("properties")); !slices.Equal(got, tags) {
			t.Errorf("%s: schema properties %v, Go fields %v", tt.name, got, tags)
		}
		want := slices.DeleteFunc(slices.Clone(tags), func(k string) bool { return slices.Contains(tt.optional, k) })
		if got := requiredKeys(tt.schema); !slices.Equal(got, want) {
			t.Errorf("%s: schema requires %v, want %v", tt.name, tt.schema["required"], want)
		}
		if tt.schema["additionalProperties"] != false {
			t.Errorf("%s: schema is not closed", tt.name)
		}
	}
	p := s.obj("properties")
	if got := fmt.Sprint(p.obj("class")["enum"]); got != fmt.Sprint(Classes()) {
		t.Errorf("class enum %s, want %v", got, Classes())
	}
	limits := map[string][2]any{
		"version const":       {p.obj("version")["const"], Version},
		"id maxLength":        {p.obj("id")["maxLength"], MaxIDBytes},
		"applies_to maxItems": {p.obj("applies_to")["maxItems"], MaxAppliesTo},
		"extension maxLength": {p.obj("applies_to").obj("items")["maxLength"], MaxExtBytes},
		"signatures maxItems": {defs.obj("signatures")["maxItems"], MaxSignatures},
		"signature minLength": {defs.obj("signatures").obj("items")["minLength"], MinSignature},
		"signature maxLength": {defs.obj("signatures").obj("items")["maxLength"], MaxSignature},
		"hint maxLength":      {p.obj("hint")["maxLength"], reader.MaxHintBytes},
		"code maxLength":      {defs.obj("fixture").obj("properties").obj("code")["maxLength"], MaxFixtureBytes},
		"sink_line maximum":   {defs.obj("fixture").obj("properties").obj("sink_line")["maximum"], MaxFixtureLines},
	}
	for name, l := range limits {
		if fmt.Sprint(l[0]) != fmt.Sprint(l[1]) {
			t.Errorf("%s: schema %v, Go %v", name, l[0], l[1])
		}
	}
}

// TestSchemaAcceptsTemplate validates the template against the published
// schema, and proves the check can fail on recipes Parse refuses.
func TestSchemaAcceptsTemplate(t *testing.T) {
	s := loadSchema(t)
	var doc any
	if err := json.Unmarshal(Template(), &doc); err != nil {
		t.Fatal(err)
	}
	if errs := validate(s, s, doc, "$"); len(errs) > 0 {
		t.Fatalf("template breaks the schema: %v", errs)
	}
	for name, edit := range map[string]func(m map[string]any){
		"unknown field":   func(m map[string]any) { m["endpoint"] = "x" },
		"unknown class":   func(m map[string]any) { m["class"] = "rce" },
		"hint too long":   func(m map[string]any) { m["hint"] = strings.Repeat("h", reader.MaxHintBytes+1) },
		"control in hint": func(m map[string]any) { m["hint"] = "a\x1bb" },
		"no fixtures":     func(m map[string]any) { delete(m, "fixtures") },
		"bad extension":   func(m map[string]any) { m["applies_to"] = []any{"../py"} },
	} {
		var m map[string]any
		_ = json.Unmarshal(Template(), &m)
		edit(m)
		if len(validate(s, s, m, "$")) == 0 {
			t.Errorf("%s: the schema accepts it", name)
		}
	}
}

func (s schemaDoc) obj(key string) schemaDoc {
	m, _ := s[key].(map[string]any)
	return m
}

func jsonTags(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

func sortedKeys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func requiredKeys(s schemaDoc) []string {
	var out []string
	for _, k := range s["required"].([]any) {
		out = append(out, k.(string))
	}
	slices.Sort(out)
	return out
}

// validate is a JSON Schema subset for this test only: the keywords
// recipe-v1.json uses. Any other keyword is an error, so a schema change
// it cannot check fails instead of passing.
func validate(root, s schemaDoc, v any, at string) []string {
	if ref, ok := s["$ref"].(string); ok {
		return validate(root, root.obj("definitions").obj(strings.TrimPrefix(ref, "#/definitions/")), v, at)
	}
	var errs []string
	for k, arg := range s {
		if err := keyword(root, k, arg, v, at); err != nil {
			errs = append(errs, err...)
		}
	}
	return errs
}

func keyword(root schemaDoc, k string, arg, v any, at string) []string {
	fail := func(f string, a ...any) []string { return []string{at + ": " + fmt.Sprintf(f, a...)} }
	switch k {
	case "$schema", "$id", "title", "description", "definitions":
		return nil
	case "type":
		if !hasType(arg, v) {
			return fail("not %v", arg)
		}
	case "const":
		if fmt.Sprint(arg) != fmt.Sprint(v) {
			return fail("not %v", arg)
		}
	case "enum":
		if !slices.Contains(arg.([]any), v) {
			return fail("not in enum")
		}
	case "pattern":
		if str, ok := v.(string); ok && !regexp.MustCompile(arg.(string)).MatchString(str) {
			return fail("does not match %s", arg)
		}
	case "minLength", "maxLength":
		if str, ok := v.(string); ok && outside(k, arg, utf8.RuneCountInString(str)) {
			return fail("%s %v", k, arg)
		}
	case "minItems", "maxItems":
		if arr, ok := v.([]any); ok && outside(k, arg, len(arr)) {
			return fail("%s %v", k, arg)
		}
	case "minimum", "maximum":
		if n, ok := v.(float64); ok && outside(k, arg, int(n)) {
			return fail("%s %v", k, arg)
		}
	case "uniqueItems", "items", "properties", "required", "additionalProperties":
		return container(root, k, arg, v, at)
	default:
		return fail("keyword %s not supported by this test", k)
	}
	return nil
}

func container(root schemaDoc, k string, arg, v any, at string) []string {
	var errs []string
	switch k {
	case "items":
		arr, _ := v.([]any)
		for i, e := range arr {
			errs = append(errs, validate(root, arg.(map[string]any), e, fmt.Sprintf("%s[%d]", at, i))...)
		}
	case "uniqueItems":
		arr, _ := v.([]any)
		for i, e := range arr {
			if slices.Index(arr, e) != i {
				errs = append(errs, at+": repeated item")
			}
		}
	case "properties":
		obj, _ := v.(map[string]any)
		for name, sub := range arg.(map[string]any) {
			if e, ok := obj[name]; ok {
				errs = append(errs, validate(root, sub.(map[string]any), e, at+"."+name)...)
			}
		}
	case "required":
		obj, _ := v.(map[string]any)
		for _, name := range arg.([]any) {
			if _, ok := obj[name.(string)]; !ok {
				errs = append(errs, fmt.Sprintf("%s: missing %v", at, name))
			}
		}
	case "additionalProperties":
		errs = append(errs, extraKeys(v, at)...)
	}
	return errs
}

// extraKeys is additionalProperties false, checked against the Go types
// by path: the closed objects are the recipe, fixtures and each fixture.
func extraKeys(v any, at string) []string {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	allowed := map[string][]string{
		"$":                     jsonTags(reflect.TypeFor[Recipe]()),
		"$.fixtures":            jsonTags(reflect.TypeFor[Fixtures]()),
		"$.fixtures.vulnerable": jsonTags(reflect.TypeFor[Fixture]()),
		"$.fixtures.safe":       jsonTags(reflect.TypeFor[Fixture]()),
	}[at]
	var errs []string
	for k := range obj {
		if !slices.Contains(allowed, k) {
			errs = append(errs, at+": unknown key "+k)
		}
	}
	return errs
}

func hasType(arg, v any) bool {
	types, ok := arg.([]any)
	if !ok {
		types = []any{arg}
	}
	for _, t := range types {
		switch t {
		case "object":
			if _, ok := v.(map[string]any); ok {
				return true
			}
		case "array":
			if _, ok := v.([]any); ok {
				return true
			}
		case "string":
			if _, ok := v.(string); ok {
				return true
			}
		case "integer":
			if n, ok := v.(float64); ok && n == float64(int(n)) {
				return true
			}
		case "null":
			if v == nil {
				return true
			}
		}
	}
	return false
}

func outside(k string, arg any, n int) bool {
	limit := int(arg.(float64))
	if strings.HasPrefix(k, "min") {
		return n < limit
	}
	return n > limit
}
