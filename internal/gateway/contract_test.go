package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Persisted line formats change additively only (architecture §4, #135).
// testdata/contract/v1 holds lines a v1 creep wrote, with synthetic values:
// the current writer must still emit every fixture field with the same JSON
// type, and the current reader must still decode the fixture. A new field
// passes; a removed or retyped one fails.
var contractDir = filepath.Join("testdata", "contract", "v1")

// TestEgressLogKeepsV1Fields compares one request and one result line the
// current writer emits for a call with every optional field set against the
// v1 fixture. The broken cases prove a removed, retyped or nested-retyped
// field fails and an added field passes.
func TestEgressLogKeepsV1Fields(t *testing.T) {
	fixture := fixtureLines(t, "egress.log")
	current := currentEgressLines(t)
	if len(fixture) != 2 || len(current) != 2 {
		t.Fatalf("got %d fixture and %d current lines, want 2 each", len(fixture), len(current))
	}
	tests := []struct {
		name  string
		edit  func(request, result map[string]any)
		match bool
	}{
		{"current writer", func(_, _ map[string]any) {}, true},
		{"field added", func(req, _ map[string]any) { req["new_field"] = "x" }, true},
		{"broken: request field removed", func(req, _ map[string]any) { delete(req, "sha256") }, false},
		{"broken: result field removed", func(_, res map[string]any) { delete(res, "tokens") }, false},
		{"broken: field retyped", func(req, _ map[string]any) { req["bytes"] = "32" }, false},
		{"broken: nested field retyped", func(_, res map[string]any) { res["tokens"] = map[string]any{"input": "12", "output": 3.0} }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, res := cloneLine(t, current[0]), cloneLine(t, current[1])
			tt.edit(req, res)
			problems := slices.Concat(shapeProblems("request", fixture[0], req), shapeProblems("result", fixture[1], res))
			checkProblems(t, problems, tt.match)
		})
	}
}

// TestEgressLogKeepsResumeFields pins the request line's optional
// `reserve` (ADR 0032) in its own additive v1 fixture, beside the original
// one (v0.4 review A2): the current writer must still emit it as a number.
func TestEgressLogKeepsResumeFields(t *testing.T) {
	fixture := fixtureLines(t, "egress-resume.log")
	current := currentEgressLines(t)
	if len(fixture) != 1 || len(current) != 2 {
		t.Fatalf("got %d fixture and %d current lines, want 1 and 2", len(fixture), len(current))
	}
	tests := []struct {
		name  string
		edit  func(request map[string]any)
		match bool
	}{
		{"current writer", func(map[string]any) {}, true},
		{"broken: reserve removed", func(req map[string]any) { delete(req, "reserve") }, false},
		{"broken: reserve retyped", func(req map[string]any) { req["reserve"] = "1024" }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := cloneLine(t, current[0])
			tt.edit(req)
			checkProblems(t, shapeProblems("request", fixture[0], req), tt.match)
		})
	}
}

// TestConsentStoreKeepsV1Format checks the current writer against the v1
// consent file and that the current reader still loads it.
func TestConsentStoreKeepsV1Format(t *testing.T) {
	fixture := fixtureLines(t, "consent.json")[0]
	current := currentConsentFile(t)
	tests := []struct {
		name  string
		edit  func(map[string]any)
		match bool
	}{
		{"current writer", func(map[string]any) {}, true},
		{"field added", func(m map[string]any) { m["new_field"] = true }, true},
		{"broken: field removed", func(m map[string]any) { delete(m, "endpoints") }, false},
		{"broken: field retyped", func(m map[string]any) { m["v"] = "1" }, false},
		{"broken: element retyped", func(m map[string]any) { m["endpoints"] = []any{443.0} }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := cloneLine(t, current)
			tt.edit(m)
			checkProblems(t, shapeProblems("consent", fixture, m), tt.match)
		})
	}
}

func TestConsentReaderLoadsV1Fixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(contractDir, "consent.json"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		data  []byte
		match bool
	}{
		{"v1 fixture", data, true},
		{"field added", bytes.Replace(data, []byte(`{"v":1`), []byte(`{"new":[1],"v":1`), 1), true},
		{"broken: endpoints retyped", bytes.Replace(data, []byte(`["https://model.example:443"]`), []byte(`"https://model.example:443"`), 1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := filepath.Join(t.TempDir(), "consent.json")
			writeStore(t, store, string(tt.data))
			keys, err := readConsentStore(store)
			loaded := err == nil && keys["https://model.example:443"]
			if loaded != tt.match {
				t.Errorf("readConsentStore: loaded=%v, err=%v; want loaded=%v", loaded, err, tt.match)
			}
		})
	}
}

// currentEgressLines sends one call whose result has a status and tokens,
// so every field the v1 writer could emit is present.
func currentEgressLines(t *testing.T) []map[string]any {
	t.Helper()
	srv := newModelServer(t, `{"usage":{"in":12,"out":3}}`)
	dir := runDir(t)
	call := testCall(srv.url("/v1/messages"))
	call.Usage = func([]byte) (Usage, bool) { return Usage{InputTokens: 12, OutputTokens: 3}, true }
	if _, err := openLog(t, dir).Send(context.Background(), srv.client(t), call); err != nil {
		t.Fatalf("Send: %v", err)
	}
	return readLines(t, dir)
}

func currentConsentFile(t *testing.T) map[string]any {
	t.Helper()
	store := filepath.Join(t.TempDir(), "creep", "consent.json")
	if err := addStoredConsent(store, "https://model.example:443"); err != nil {
		t.Fatalf("addStoredConsent: %v", err)
	}
	data, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	return decodeObject(t, data)
}

func fixtureLines(t *testing.T, name string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(contractDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var lines []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		lines = append(lines, decodeObject(t, line))
	}
	return lines
}

func decodeObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &m); err != nil {
		t.Fatalf("decode %q: %v", data, err)
	}
	return m
}

func cloneLine(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return decodeObject(t, data)
}

func checkProblems(t *testing.T, problems []string, match bool) {
	t.Helper()
	if match && len(problems) > 0 {
		t.Errorf("the current format drops or retypes fixture fields (additive changes only, §4):\n%q", problems)
	}
	if !match && len(problems) == 0 {
		t.Error("the shape comparison missed a removed or retyped field")
	}
}

// shapeProblems lists every fixture field that got lacks or holds with
// another JSON type, recursing into objects and the first array element.
// Fields only in got are additive and fine.
func shapeProblems(path string, fixture, got any) []string {
	if jsonKind(fixture) != jsonKind(got) {
		return []string{fmt.Sprintf("%s: %s, want %s", path, jsonKind(got), jsonKind(fixture))}
	}
	switch f := fixture.(type) {
	case map[string]any:
		return objectProblems(path, f, got.(map[string]any))
	case []any:
		g := got.([]any)
		if len(f) == 0 || len(g) == 0 {
			return nil
		}
		return shapeProblems(path+"[0]", f[0], g[0])
	}
	return nil
}

func objectProblems(path string, fixture, got map[string]any) []string {
	var problems []string
	for _, key := range slices.Sorted(maps.Keys(fixture)) {
		value, ok := got[key]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s.%s: missing", path, key))
			continue
		}
		problems = append(problems, shapeProblems(path+"."+key, fixture[key], value)...)
	}
	return problems
}

func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}
