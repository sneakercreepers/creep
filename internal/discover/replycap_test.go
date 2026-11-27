package discover

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

// lengthReply is an OpenAI-compatible reply cut off at max_tokens.
var lengthReply = []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"{\"entries\":[{\"file\":0,"},"finish_reason":"length"}]}`)

// Acceptance (#362): a discovery reply cut off at its cap is a counted
// retry: the next attempt can still read the batch in full, and when every
// attempt is cut off the files are truncated, not parse_failed, and the
// run goes on. Each call asks for the batch's discovery reply cap.
func TestTruncatedReplyIsCountedRetry(t *testing.T) {
	tests := []struct {
		name      string
		cutoffs   int // replies cut off before honest ones
		wantCalls int
		cov       Coverage
		reason    Reason
	}{
		{"cut off once, then whole", 1, 2, CoverageReadFull, ReasonNone},
		{"cut off on every attempt", 2, 2, CoverageTruncated, ReasonTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var caps []int
			send := func(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
				var body struct {
					MaxTokens int `json:"max_tokens"`
				}
				if err := json.Unmarshal(c.Payload, &body); err != nil {
					return nil, err
				}
				caps = append(caps, body.MaxTokens)
				if len(caps) <= tt.cutoffs {
					return &gateway.Reply{Status: 200, Body: lengthReply}, nil
				}
				prompt, err := userTurn(c.Payload)
				if err != nil {
					return nil, err
				}
				content, err := json.Marshal(honest(parseSections(prompt)))
				if err != nil {
					return nil, err
				}
				out, err := chatCompletion(content)
				return &gateway.Reply{Status: 200, Body: out}, err
			}
			h, err := models.NewHTTP(models.Options{
				Contract: "openai", Endpoint: "https://models.replay.invalid/v1", Model: replayModelName,
				Structured: models.StructuredSchema, MaxOutputTokens: 1024, Retries: 1, Send: send,
			})
			if err != nil {
				t.Fatal(err)
			}
			res, err := discoverFiles(t, TierS, map[string]string{"app.py": flaskApp}, h)
			if err != nil {
				t.Fatalf("a cut-off reply must not stop the run: %v", err)
			}
			if f := fileOf(t, res, 0); f.Coverage != tt.cov || f.Reason != tt.reason || len(caps) != tt.wantCalls {
				t.Errorf("file %+v after %d calls; want coverage %d reason %s after %d", f, len(caps), tt.cov, tt.reason, tt.wantCalls)
			}
			want, _ := ReplyTokens(TierS, 2) // the file and the canary
			for _, c := range caps {
				if c != want {
					t.Errorf("max_tokens %d, want the discovery cap %d", c, want)
				}
			}
		})
	}
}
