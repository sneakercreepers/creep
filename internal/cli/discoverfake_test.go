package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/redact"
)

// discoverySection is one FILE section of a discovery request, read back
// the way a model would see it.
type discoverySection struct {
	num   int
	lines []string
}

// userContent returns the user turn of an OpenAI-compatible request body.
func userContent(body []byte) string {
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &req) != nil {
		return ""
	}
	for _, m := range req.Messages {
		if m.Role == "user" {
			return m.Content
		}
	}
	return ""
}

// discoverySections parses the FILE sections of a discovery user turn; a
// reader or calibration request has none.
func discoverySections(prompt string) []discoverySection {
	var secs []discoverySection
	for _, line := range strings.Split(prompt, "\n") {
		var n int
		if strings.HasPrefix(line, "FILE ") {
			if _, err := fmt.Sscanf(line, "FILE %d ", &n); err == nil {
				secs = append(secs, discoverySection{num: n})
				continue
			}
		}
		if _, text, ok := strings.Cut(line, "| "); ok && len(secs) > 0 {
			secs[len(secs)-1].lines = append(secs[len(secs)-1].lines, text)
		}
	}
	return secs
}

// canaryAt finds the planted canary as internal/discover/canary.txt lays
// it out: its section, entry line and sink line.
func canaryAt(secs []discoverySection) (file, entry, sink int, ok bool) {
	for _, s := range secs {
		entry, sink = 0, 0
		for i, l := range s.lines {
			if strings.Contains(l, `.get("/files/`) {
				entry = i + 1
			}
			if strings.Contains(l, "fs.readFile(String(req.query.name)") {
				sink = i + 1
			}
		}
		if entry > 0 && sink > 0 {
			return s.num, entry, sink, true
		}
	}
	return 0, 0, 0, false
}

// testSeed is a fixed canary seed for tests that build a Discoverer.
var testSeed = [32]byte{'c', 'r', 'e', 'e', 'p', 1}

// discoverHere walks the repository in the current directory and runs
// discovery on it with m as the model, as scan does.
func discoverHere(t *testing.T, m *fakeModel, tier calibrate.Tier) repoScan {
	t.Helper()
	ctx := context.Background()
	root, err := os.OpenRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	files, err := walkRepo(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	dtier, err := discoverTier(tier)
	if err != nil {
		t.Fatal(err)
	}
	red, err := redact.New()
	if err != nil {
		t.Fatal(err)
	}
	model, err := models.NewHTTP(modelOptions(config.Model{Contract: "openai", Endpoint: "https://models.example.invalid/v1", Name: "test-model"}, models.Key{}, m.send))
	if err != nil {
		t.Fatal(err)
	}
	d := discover.Discoverer{Redactor: red, Model: model, Tier: dtier, Seed: testSeed, Read: readRepoFile(root)}
	rs, err := discoverRepo(ctx, d, files)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// discoveryAnswer answers a discovery request as a model that reports the
// canary and nothing else (missCanary: not even that), so every real
// candidate comes from the tripwire. ok is false for any other request.
func discoveryAnswer(body []byte, missCanary bool) (answer map[string]any, ok bool) {
	secs := discoverySections(userContent(body))
	if len(secs) == 0 {
		return nil, false
	}
	answer = map[string]any{"entries": []any{}, "sinks": []any{}, "auth": []any{}}
	file, entry, sink, found := canaryAt(secs)
	if !found || missCanary {
		return answer, true
	}
	answer["entries"] = []any{map[string]any{"file": file, "start": entry, "end": entry + 2, "kind": "http"}}
	answer["sinks"] = []any{map[string]any{"file": file, "line": sink, "kind": "file", "entry": 0}}
	return answer, true
}
