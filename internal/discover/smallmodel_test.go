package discover

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

// smallModel is the base model of the pinned Ollama model (#355, #367).
const smallModel = "qwen2.5-coder:1.5b"

// Acceptance (#362): the small-model batch that failed before (its canary
// is off the exact lines, so the v1 check missed it and every file was
// parse_failed) gives a complete Result now. The reply is built in memory
// in the shape of the qwen2.5-coder:1.5b replies audited in #355 and #367
// (canary entry and sink cited one line off); the live recording of the
// pinned model is TestLiveSmallModelReplay's (#356).
func TestSmallModelBatchReplay(t *testing.T) {
	app := loadApp(t, "flask")
	var replies []reply
	var canaries []canary
	send := func(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
		prompt, err := userTurn(c.Payload)
		if err != nil {
			return nil, err
		}
		content, err := smallModelReply(app, parseSections(prompt))
		if err != nil {
			return nil, err
		}
		body, err := chatCompletion(content)
		if err != nil {
			return nil, err
		}
		rep, cn, ok := recordedBatch(c.Payload, body)
		if !ok {
			return nil, errors.New("reply does not decode")
		}
		replies, canaries = append(replies, rep), append(canaries, cn)
		return &gateway.Reply{ID: "synthesized", Status: 200, Body: body}, nil
	}
	res, err := smallDiscoverer(t, app, "http://127.0.0.1:11434/v1", smallModel, send).Run(context.Background(), []string{app.file})
	if err != nil || !res.Complete() {
		t.Fatalf("small-model batch: %v, files %+v; want complete", err, res.Files)
	}
	if len(replies) != 1 {
		t.Fatalf("%d discovery calls, want one batch", len(replies))
	}
	if exactCanary(replies[0], canaries[0]) || !canaries[0].found(replies[0]) {
		t.Error("the reply must cite the canary off its exact lines and inside the window")
	}
}

// smallDiscoverer runs discovery at tier S on the app's vulnerable variant
// with the small model's client settings.
func smallDiscoverer(t *testing.T, app testApp, endpoint, name string, send models.SendFunc) Discoverer {
	t.Helper()
	h, err := models.NewHTTP(models.Options{
		Contract: "openai", Endpoint: endpoint, Model: name,
		Structured: models.StructuredSchema, MaxOutputTokens: 1024, Retries: 1, Send: send,
	})
	if err != nil {
		t.Fatal(err)
	}
	files := os.DirFS(filepath.Join(appsDir, app.name, variantVulnerable))
	return Discoverer{
		Redactor: newRedactor(t), Model: h, Tier: TierS, Seed: testSeed,
		Read: func(p string) ([]byte, error) { return fs.ReadFile(files, p) },
	}
}

// smallModelReply is synthesizedReply with the canary cited one line off,
// as the small model did: entry on the line after the route, sink on the
// line before the call.
func smallModelReply(app testApp, secs []promptSection) ([]byte, error) {
	c, _ := canaryOf(secs)
	a := Answer{
		Entries: []EntryProposal{entryAt(c.section, c.entry+1, c.entry+1, "http")},
		Sinks:   []SinkProposal{sinkAt(c.section, c.sink-1, "file", 0)},
		Auth:    []AuthProposal{},
	}
	for _, s := range secs {
		if s.num != c.section {
			app.propose(&a, s.num)
		}
	}
	return json.Marshal(a)
}

// recordedBatch decodes the reply a recorded call got and the canary its
// prompt held.
func recordedBatch(payload, body []byte) (reply, canary, bool) {
	prompt, err := userTurn(payload)
	if err != nil {
		return reply{}, canary{}, false
	}
	c, ok := canaryOf(parseSections(prompt))
	var env struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if !ok || json.Unmarshal(body, &env) != nil || len(env.Choices) != 1 {
		return reply{}, canary{}, false
	}
	var a Answer
	if json.Unmarshal([]byte(env.Choices[0].Message.Content), &a) != nil || a.Validate() != nil {
		return reply{}, canary{}, false
	}
	rep, err := a.reply()
	return rep, c, err == nil
}

// exactCanary is the v1 canary check, with no window.
func exactCanary(a reply, c canary) bool {
	entry := slices.ContainsFunc(a.entries, func(e entryRec) bool {
		return e.file == c.section && e.start <= c.entry && c.entry <= e.end
	})
	sink := slices.ContainsFunc(a.sinks, func(s sinkRec) bool { return s.file == c.section && s.line == c.sink })
	return entry && sink
}
