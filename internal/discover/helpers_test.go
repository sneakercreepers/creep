package discover

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/redact"
)

const replayModelName = "replay-model"

var testSeed = [32]byte{0x63, 0x72, 0x65, 0x65, 0x70, 1, 2, 3}

// promptSection is one FILE section of a user turn, read back the way a
// model would see it.
type promptSection struct {
	num   int
	lines []string
}

// userTurn returns the user message of an OpenAI-compatible request body.
func userTurn(payload []byte) (string, error) {
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return "", err
	}
	for _, m := range req.Messages {
		if m.Role == "user" {
			return m.Content, nil
		}
	}
	return "", errors.New("no user message")
}

func parseSections(prompt string) []promptSection {
	var secs []promptSection
	for _, line := range strings.Split(strings.TrimSuffix(prompt, "\n"), "\n") {
		var n int
		if _, err := fmt.Sscanf(line, "FILE %d ", &n); err == nil && strings.HasPrefix(line, "FILE ") {
			secs = append(secs, promptSection{num: n})
			continue
		}
		if _, text, ok := strings.Cut(line, "| "); ok && len(secs) > 0 {
			secs[len(secs)-1].lines = append(secs[len(secs)-1].lines, text)
		}
	}
	return secs
}

// canaryOf finds the canary section and its entry and sink lines, as the
// template in canary.txt places them.
func canaryOf(secs []promptSection) (canary, bool) {
	for _, s := range secs {
		c := canary{section: s.num}
		for i, l := range s.lines {
			if strings.Contains(l, `.get("/files/`) {
				c.entry = i + 1
			}
			if strings.Contains(l, "fs.readFile(String(req.query.name)") {
				c.sink = i + 1
			}
		}
		if c.entry > 0 && c.sink > 0 {
			return c, true
		}
	}
	return canary{}, false
}

func num(n int) *int { return &n }

func entryAt(file, start, end int, kind string) EntryProposal {
	return EntryProposal{File: num(file), Start: num(start), End: num(end), Kind: kind}
}

func sinkAt(file, line int, kind string, entry int) SinkProposal {
	return SinkProposal{File: num(file), Line: num(line), Kind: kind, Entry: num(entry)}
}

func authAt(file, start, end int) AuthProposal {
	return AuthProposal{File: num(file), Start: num(start), End: num(end)}
}

// honest reports nothing but the canary: its entry is Entries[0].
func honest(secs []promptSection) Answer {
	c, _ := canaryOf(secs)
	return Answer{
		Entries: []EntryProposal{entryAt(c.section, c.entry, c.entry+2, "http")},
		Sinks:   []SinkProposal{sinkAt(c.section, c.sink, "file", 0)},
		Auth:    []AuthProposal{},
	}
}

// replyFunc turns the sections a call shows into the model's output.
type replyFunc func(secs []promptSection) ([]byte, error)

// answering marshals what build returns as the model's output.
func answering(build func(secs []promptSection) any) replyFunc {
	return func(secs []promptSection) ([]byte, error) { return json.Marshal(build(secs)) }
}

// fakeClient is an OpenAI-compatible client whose model is reply; prompts
// collects every user turn sent.
func fakeClient(t *testing.T, reply replyFunc, prompts *[]string) *models.HTTP {
	t.Helper()
	send := func(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
		prompt, err := userTurn(c.Payload)
		if err != nil {
			return nil, err
		}
		if prompts != nil {
			*prompts = append(*prompts, prompt)
		}
		content, err := reply(parseSections(prompt))
		if err != nil {
			return nil, err
		}
		body, err := chatCompletion(content)
		return &gateway.Reply{ID: "fake", Status: 200, Body: body}, err
	}
	return newClient(t, send)
}

func newClient(t *testing.T, send models.SendFunc) *models.HTTP {
	t.Helper()
	h, err := models.NewHTTP(models.Options{
		Contract: "openai", Endpoint: "https://models.replay.invalid/v1", Model: replayModelName,
		Structured: models.StructuredSchema, MaxOutputTokens: 4096, Send: send,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// chatCompletion wraps content as an OpenAI-compatible reply body.
func chatCompletion(content []byte) ([]byte, error) {
	message := map[string]any{"role": "assistant", "content": string(content)}
	return json.Marshal(map[string]any{
		"id": "chatcmpl-replay", "object": "chat.completion", "model": replayModelName,
		"choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": "stop"}},
		"usage":   map[string]int{"prompt_tokens": 0, "completion_tokens": len(content)},
	})
}

func newRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// discoverFiles runs a Discoverer over files at tier, in sorted path order.
func discoverFiles(t *testing.T, tier Tier, files map[string]string, model *models.HTTP) (Result, error) {
	t.Helper()
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	d := Discoverer{
		Redactor: newRedactor(t), Model: model, Tier: tier, Seed: testSeed,
		Read: func(p string) ([]byte, error) {
			s, ok := files[p]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return []byte(s), nil
		},
	}
	return d.Run(context.Background(), paths)
}

// fileOf returns the result for the path at index i of the sorted paths.
func fileOf(t *testing.T, res Result, i int) File {
	t.Helper()
	if i >= len(res.Files) {
		t.Fatalf("no file %d in %d files", i, len(res.Files))
	}
	return res.Files[i]
}
