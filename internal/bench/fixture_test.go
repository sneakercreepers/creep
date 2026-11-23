package bench

import (
	"bytes"
	"strings"
	"testing"
)

func TestPublishedFixtureParses(t *testing.T) {
	f, err := Published()
	if err != nil {
		t.Fatal(err)
	}
	if !f.Synthesized || len(f.Replies) == 0 {
		t.Fatalf("published fixture: synthesized %v, %d replies", f.Synthesized, len(f.Replies))
	}
}

func TestParseFixtureRejects(t *testing.T) {
	hashA, hashB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	good := `{"schema_version": 1, "synthesized": false, "model": {"contract": "openai", "endpoint": "http://127.0.0.1:11434/v1", "name": "m", "structured": "json_schema", "max_output_tokens": 1024, "retries": 1}, "replies": [{"request_sha256": "` + hashA + `", "body": "{}"}, {"request_sha256": "` + hashB + `", "body": "{}"}]}`
	if _, err := ParseFixture(strings.NewReader(good)); err != nil {
		t.Fatalf("good fixture: %v", err)
	}
	tests := map[string]string{
		"version":         strings.Replace(good, `"schema_version": 1`, `"schema_version": 2`, 1),
		"unknown field":   strings.Replace(good, `"synthesized"`, `"extra": 1, "synthesized"`, 1),
		"trailing data":   good + `{}`,
		"command model":   strings.Replace(good, `"openai"`, `"command"`, 1),
		"no model name":   strings.Replace(good, `"name": "m"`, `"name": ""`, 1),
		"control in name": strings.Replace(good, `"name": "m"`, `"name": "m\n# injected"`, 1),
		"uppercase hash":  strings.Replace(good, hashA, strings.Repeat("A", 64), 1),
		"short hash":      strings.Replace(good, hashA, "abc", 1),
		"unsorted":        strings.Replace(strings.Replace(strings.Replace(good, hashA, "x", 1), hashB, hashA, 1), `"x"`, `"`+hashB+`"`, 1),
		"repeated":        strings.Replace(good, hashB, hashA, 1),
		"oversized":       good + strings.Repeat(" ", MaxFixtureBytes),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseFixture(strings.NewReader(data)); err == nil {
				t.Fatal("parsed")
			}
		})
	}
}

func TestRecorder(t *testing.T) {
	rec := NewRecorder()
	rec.Record([]byte("b"), []byte("first"))
	rec.Record([]byte("b"), []byte("second"))
	rec.Record([]byte("a"), []byte("reply a"))
	rec.Record([]byte("c"), []byte{0xff, 0xfe})
	if got, ok := rec.Lookup([]byte("b")); !ok || string(got) != "first" {
		t.Fatalf("a body asked again got %q, want the first reply", got)
	}
	if _, ok := rec.Lookup([]byte("c")); ok {
		t.Fatal("a reply that is not UTF-8 was kept; it would replay changed")
	}
	f := rec.Fixture(FixtureModel{Contract: "openai", Name: "m"}, false)
	data, err := f.JSON()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseFixture(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("a recorded fixture does not parse: %v", err)
	}
	idx := back.Index()
	if len(idx) != 2 || string(idx[RequestHash([]byte("a"))]) != "reply a" || string(idx[RequestHash([]byte("b"))]) != "first" {
		t.Fatalf("round trip: %v", idx)
	}
}
