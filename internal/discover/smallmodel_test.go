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

// smallFixture is a discovery batch of a small local model on the flask
// app at tier S. SYNTHESIZED in the shape of the qwen2.5-coder:1.5b
// replies audited in #355 and #367 (keys in the schema's order, canary
// entry and sink cited one line off), because no live recording is
// committed yet. A reviewed live recording is owed by #356
// (https://github.com/sneakercreepers/creep/issues/356): record it through
// Discoverer.Run with smallModel, TierS and testSeed and replace this one.
// Regenerate the synthesized one:
// go test ./internal/discover -run TestSmallModelBatchReplay -update
const (
	smallFixture = "testdata/replay/small-synthesized/flask"
	smallModel   = "qwen2.5-coder:1.5b"
)

// Acceptance (#362): the small-model batch that failed before (its canary
// is off the exact lines, so the v1 check missed it and every file was
// parse_failed) replays to a complete Result now, with no model call.
func TestSmallModelBatchReplay(t *testing.T) {
	app := loadApp(t, "flask")
	store, mode := fixtureStoreIn(t, smallFixture)
	var replies []reply
	var canaries []canary
	send := storeSend(store, mode, func(prompt string) ([]byte, error) {
		if !*update {
			return nil, errors.New("replay must not call the model")
		}
		return smallModelReply(app, parseSections(prompt))
	})
	seen := func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
		r, err := send(ctx, c)
		if err == nil {
			rep, cn, ok := recordedBatch(c.Payload, r.Body)
			if !ok {
				return nil, errors.New("recorded reply does not decode")
			}
			replies, canaries = append(replies, rep), append(canaries, cn)
		}
		return r, err
	}
	h, err := models.NewHTTP(models.Options{
		Contract: "openai", Endpoint: "http://127.0.0.1:11434/v1", Model: smallModel,
		Structured: models.StructuredSchema, MaxOutputTokens: 1024, Retries: 1, Send: seen,
	})
	if err != nil {
		t.Fatal(err)
	}
	files := os.DirFS(filepath.Join(appsDir, app.name, variantVulnerable))
	d := Discoverer{
		Redactor: newRedactor(t), Model: h, Tier: TierS, Seed: testSeed,
		Read: func(p string) ([]byte, error) { return fs.ReadFile(files, p) },
	}
	res, err := d.Run(context.Background(), []string{app.file})
	if err != nil || !res.Complete() {
		t.Fatalf("small-model batch: %v, files %+v; want complete", err, res.Files)
	}
	if len(replies) != 1 {
		t.Fatalf("%d discovery calls, want one batch", len(replies))
	}
	if exactCanary(replies[0], canaries[0]) || !canaries[0].found(replies[0]) {
		t.Error("the fixture must cite the canary off its exact lines and inside the window")
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
