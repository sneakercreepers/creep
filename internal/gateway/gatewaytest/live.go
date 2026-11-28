package gatewaytest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// Live recording (#356): a replay fixture is re-recorded from a real model
// only when both variables are set, in the live-record workflow, which
// runs a pinned Ollama model on the CI runner. LiveEndpoint must be
// http://127.0.0.1:<port>/v1: the runner's own model, never a cloud one.
const (
	LiveEndpointEnv = "CREEP_LIVE_ENDPOINT"
	LiveModelEnv    = "CREEP_LIVE_MODEL"
)

// LiveSettings is the model a live recording runs against.
type LiveSettings struct {
	Endpoint string // base URL, http://127.0.0.1:<port>/v1
	Model    string
}

// ErrNotLoopback means a live endpoint is not plain HTTP on 127.0.0.1.
var ErrNotLoopback = errors.New("live endpoint must be http://127.0.0.1:<port>/v1")

// LiveFromEnv returns the live model the environment names, ok false when
// neither variable is set. One without the other, or an endpoint that is
// not the runner's loopback, is an error, so a half-set run fails instead
// of quietly writing synthesized fixtures.
func LiveFromEnv() (LiveSettings, bool, error) {
	s := LiveSettings{Endpoint: os.Getenv(LiveEndpointEnv), Model: os.Getenv(LiveModelEnv)}
	if s.Endpoint == "" && s.Model == "" {
		return LiveSettings{}, false, nil
	}
	if s.Model == "" {
		return LiveSettings{}, false, fmt.Errorf("%s is set without %s", LiveEndpointEnv, LiveModelEnv)
	}
	u, err := url.Parse(s.Endpoint)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.RawQuery != "" {
		return LiveSettings{}, false, ErrNotLoopback
	}
	return s, true, nil
}

// Live returns a send function that forwards each call to its endpoint
// through the real gateway: consent and egress.allow for the endpoint's
// origin only, a bounded budget and egress.log in a temporary run
// directory. Each reply body is reduced by Normalize before it is
// returned, so what a fixture records carries no response ID, timestamp
// or routing field of the provider.
func Live(tb testing.TB, s LiveSettings) func(context.Context, gateway.Call) (*gateway.Reply, error) {
	tb.Helper()
	u, err := url.Parse(s.Endpoint)
	if err != nil {
		tb.Fatal(err)
	}
	client, err := gateway.NewClient(gateway.Options{Allow: []string{u.Host}})
	if err != nil {
		tb.Fatal(err)
	}
	log := liveLog(tb, u.Scheme+"://"+u.Host)
	return func(ctx context.Context, call gateway.Call) (*gateway.Reply, error) {
		r, err := log.Send(ctx, client, call)
		if err != nil {
			return nil, err
		}
		if r.Status != 200 {
			return nil, fmt.Errorf("live model answered status %d", r.Status)
		}
		body, err := Normalize(r.Body)
		if err != nil {
			return nil, err
		}
		return &gateway.Reply{ID: "live", Status: r.Status, Body: body}, nil
	}
}

// liveLog opens egress.log in a private temporary run directory, with
// consent for origin alone.
func liveLog(tb testing.TB, origin string) *gateway.EgressLog {
	tb.Helper()
	consent, err := gateway.NewConsent(gateway.ConsentOptions{CI: true, Policy: []string{origin}})
	if err != nil {
		tb.Fatal(err)
	}
	budget, err := gateway.NewBudget(gateway.BudgetOptions{MaxTokens: 50_000_000, MaxCalls: 10_000, MaxConcurrency: 1})
	if err != nil {
		tb.Fatal(err)
	}
	// TempDir is created 0700, as OpenEgressLog requires of a run directory.
	log, err := gateway.OpenEgressLog(tb.TempDir(), consent, budget)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = log.Close() })
	return log
}

// chatReply is the part of an OpenAI-compatible reply that a replay reads.
type chatReply struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Model   string       `json:"model"`
	Choices []chatChoice `json:"choices"`
	Usage   chatUsage    `json:"usage"`
}

type chatChoice struct {
	Index        int         `json:"index"`
	Message      chatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

// NormalizedID replaces the provider's response ID in a normalized reply.
const NormalizedID = "chatcmpl-replay"

// Normalize keeps of an OpenAI-compatible reply body only the model name,
// each choice's message and finish reason, and the token counts: the
// message content, which is what the model said, stays byte for byte.
// The response ID becomes NormalizedID; created, system_fingerprint,
// provider and every other field are dropped.
func Normalize(body []byte) ([]byte, error) {
	var r chatReply
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("normalize live reply: %w", err)
	}
	if len(r.Choices) == 0 {
		return nil, errors.New("normalize live reply: no choices")
	}
	r.ID, r.Object = NormalizedID, "chat.completion"
	return json.Marshal(r)
}
