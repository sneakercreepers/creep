package recipe

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/redact"
)

// sinkLine finds the reader's HYPOTHESIS line in a request body.
var sinkLine = regexp.MustCompile(`HYPOTHESIS: [a-z_]+, source line [0-9]+, sink line ([0-9]+)`)

// fakeModel answers reader calls with no network, like the CLI's fake:
// a verdict per sink line ("" is not_vulnerable), or an error, and it keeps
// every call it got.
type fakeModel struct {
	verdict map[int]string
	fail    error
	calls   []gateway.Call
}

func (m *fakeModel) send(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
	m.calls = append(m.calls, c)
	if m.fail != nil {
		return nil, m.fail
	}
	match := sinkLine.FindSubmatch(c.Payload)
	if match == nil {
		return nil, errors.New("fake model: no hypothesis in request")
	}
	sink, _ := strconv.Atoi(string(match[1]))
	verdict := m.verdict[sink]
	if verdict == "" {
		verdict = "not_vulnerable"
	}
	content, err := json.Marshal(map[string]any{"verdict": verdict, "evidence": []map[string]int{{"start": sink, "end": sink}}, "confidence": 80})
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]any{
		"id": "chatcmpl-fake", "object": "chat.completion", "model": "test-model",
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": string(content)}, "finish_reason": "stop"}},
		"usage":   map[string]int{"prompt_tokens": 0, "completion_tokens": len(content)},
	})
	return &gateway.Reply{ID: "fake", Status: 200, Body: body}, err
}

// checker is a Checker whose model is m, at tier.
func checker(t *testing.T, m *fakeModel, tier reader.Tier) Checker {
	t.Helper()
	h, err := models.NewHTTP(models.Options{
		Contract: "openai", Endpoint: "https://models.example.invalid/v1", Model: "test-model",
		Structured: models.StructuredSchema, MaxOutputTokens: 512, Send: m.send,
	})
	if err != nil {
		t.Fatal(err)
	}
	red, err := redact.New()
	if err != nil {
		t.Fatal(err)
	}
	return Checker{Model: h, Redactor: red, Tier: tier}
}

// templateRecipe is the embedded template as a Recipe to edit.
func templateRecipe(t *testing.T) Recipe {
	t.Helper()
	var r Recipe
	if err := json.Unmarshal(Template(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// encode turns r back into recipe JSON.
func encode(t *testing.T, r Recipe) []byte {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// acceptPoC stands in for the CLI's verify check.
func acceptPoC(string, json.RawMessage) error { return nil }

// rightModel flags the template's vulnerable fixture (sink line 9) and
// clears its safe one (sink line 8).
func rightModel() *fakeModel { return &fakeModel{verdict: map[int]string{9: "vulnerable"}} }
