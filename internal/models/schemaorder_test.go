package models

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// Acceptance (#362): a schema whose properties are in alphabetical order
// instead of reasoning order (what json.Marshal of a Go map writes) fails,
// at any depth, so no schema creep sends has "end" before "start".
func TestCheckPropertyOrder(t *testing.T) {
	ordered := `{"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"}},"required":["start","end"],"additionalProperties":false}`
	tests := []struct {
		name   string
		schema string
		want   error
	}{
		{"reasoning order", ordered, nil},
		{"alphabetical order", `{"type":"object","properties":{"end":{"type":"integer"},"start":{"type":"integer"}},"required":["start","end"]}`, ErrPropertyOrder},
		{"nested in array items", `{"type":"object","properties":{"spans":{"type":"array","items":{"type":"object","properties":{"end":{},"start":{}},"required":["start","end"]}}},"required":["spans"]}`, ErrPropertyOrder},
		{"nested in anyOf", `{"anyOf":[{"type":"null"},{"type":"object","properties":{"end":{},"start":{}},"required":["start","end"]}]}`, ErrPropertyOrder},
		{"nested in $defs", `{"$defs":{"span":{"type":"object","properties":{"end":{},"start":{}},"required":["start","end"]}}}`, ErrPropertyOrder},
		{"property not required", `{"type":"object","properties":{"start":{},"end":{}},"required":["start"]}`, ErrPropertyOrder},
		{"required not a property", `{"type":"object","properties":{"start":{}},"required":["start","end"]}`, ErrPropertyOrder},
		{"no required", `{"type":"object","properties":{"start":{}}}`, ErrPropertyOrder},
		{"duplicate key", `{"type":"object","properties":{"start":{},"start":{}},"required":["start","start"]}`, ErrPropertyOrder},
		{"no properties", `{"type":"string","enum":["a","b"]}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckPropertyOrder(json.RawMessage(tt.schema))
			if !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
				t.Errorf("CheckPropertyOrder = %v, want %v", err, tt.want)
			}
		})
	}
}

// Complete refuses to send a schema out of order: the check sits on the
// only path to the gateway, so a new schema cannot skip it.
func TestCompleteRefusesUnorderedSchema(t *testing.T) {
	sent := 0
	h, err := NewHTTP(Options{
		Contract: "openai", Endpoint: "https://models.test.invalid/v1", Model: "m",
		Structured: StructuredSchema, MaxOutputTokens: 64,
		Send: func(context.Context, gateway.Call) (*gateway.Reply, error) {
			sent++
			return nil, errors.New("unreachable")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	schema := `{"type":"object","properties":{"end":{"type":"integer"},"start":{"type":"integer"}},"required":["start","end"],"additionalProperties":false}`
	_, err = Complete[struct{}](context.Background(), h, Request{Purpose: "test", Prompt: "p", Schema: json.RawMessage(schema)})
	if !errors.Is(err, ErrRequest) || !errors.Is(err, ErrPropertyOrder) || sent != 0 {
		t.Errorf("Complete = %v after %d sends, want ErrRequest wrapping ErrPropertyOrder and no send", err, sent)
	}
}

// A per-call reply cap replaces the client's max_tokens in the body and in
// the gateway reservation; 0 keeps the client's, and one out of range is
// refused before anything is sent.
func TestRequestReplyCap(t *testing.T) {
	tests := []struct {
		name      string
		cap       int
		wantMax   int
		wantError bool
	}{
		{"client default", 0, 64, false},
		{"larger step cap", 4096, 4096, false},
		{"negative", -1, 0, true},
		{"over the limit", maxOutputTokens + 1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got gateway.Call
			h, err := NewHTTP(Options{
				Contract: "openai", Endpoint: "https://models.test.invalid/v1", Model: "m",
				Structured: StructuredPrompt, MaxOutputTokens: 64,
				Send: func(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
					got = c
					return &gateway.Reply{Status: 200, Body: []byte(`{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}]}`)}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = Complete[struct{}](context.Background(), h, Request{Purpose: "test", Prompt: "p", MaxOutputTokens: tt.cap})
			if tt.wantError {
				if !errors.Is(err, ErrRequest) || got.Payload != nil {
					t.Fatalf("Complete = %v, want ErrRequest and no send", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var body struct {
				MaxTokens int `json:"max_tokens"`
			}
			if err := json.Unmarshal(got.Payload, &body); err != nil {
				t.Fatal(err)
			}
			if body.MaxTokens != tt.wantMax || got.ReserveTokens != len(got.Payload)+tt.wantMax {
				t.Errorf("max_tokens %d, reserve %d; want %d and payload+%d", body.MaxTokens, got.ReserveTokens, tt.wantMax, tt.wantMax)
			}
		})
	}
}
