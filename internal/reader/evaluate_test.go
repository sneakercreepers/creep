package reader

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// Evaluate sends the tier's system prompt, Slice.Text as the user turn and
// the slice's redaction counts, so egress.log can account for them, and
// refuses an unknown tier or a slice cut for another tier before any call.
func TestEvaluateCall(t *testing.T) {
	slice := Slice{
		Hypothesis: 3,
		Text:       "HYPOTHESIS: sql_injection, source line 1, sink line 2\nCODE:\n1| def f():\n2|     run([REDACTED:password:1])\n",
		Shown:      []LineRange{{Start: 1, End: 2}},
		Redactions: map[string]int{"password": 1},
	}
	vulnerable := appHypothesis{variant: variantVulnerable, sink: 2}
	safe := appHypothesis{variant: variantSafe, sink: 2}
	tests := []struct {
		name    string
		tier    Tier
		sliced  Tier // the tier the slice was cut for
		partial bool // the slice was cut to fit
		answer  appHypothesis
		verdict Verdict
		want    error
	}{
		{"tier M", TierM, TierM, false, vulnerable, VerdictVulnerable, nil},
		{"tier S", TierS, TierS, false, vulnerable, VerdictVulnerable, nil},
		{"tier L", TierL, TierL, false, safe, VerdictNotVulnerable, nil},
		// #175: a not_vulnerable from a cut slice keeps Partial, so the
		// report can show partial coverage instead of a clean verdict.
		{"partial slice not vulnerable", TierM, TierM, true, safe, VerdictNotVulnerable, nil},
		{"unknown tier", Tier("XL"), Tier("XL"), false, vulnerable, 0, ErrTier},
		// #204: an M-budget slice under the S prompt, or the reverse.
		{"M slice under S prompt", TierS, TierM, false, vulnerable, 0, ErrTier},
		{"S slice under L prompt", TierL, TierS, false, vulnerable, 0, ErrTier},
		{"slice with no tier", TierM, "", false, vulnerable, 0, ErrTier},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []gateway.Call
			client, err := replayClient(func(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
				calls = append(calls, c)
				body, err := synthesizedReply(tt.answer)
				return &gateway.Reply{Status: 200, Body: body}, err
			})
			if err != nil {
				t.Fatal(err)
			}
			in := slice
			in.Partial, in.Tier = tt.partial, tt.sliced
			sig, err := Evaluate(context.Background(), client, tt.tier, in)
			if tt.want != nil {
				if !errors.Is(err, tt.want) || len(calls) != 0 {
					t.Fatalf("err = %v after %d calls, want %v before any", err, len(calls), tt.want)
				}
				return
			}
			if err != nil || sig.Hypothesis != 3 || sig.Verdict != tt.verdict || sig.Partial != tt.partial {
				t.Fatalf("Evaluate = %+v, %v", sig, err)
			}
			if len(calls) != 1 {
				t.Fatalf("%d calls, want 1", len(calls))
			}
			checkCall(t, calls[0], tt.tier, slice)
		})
	}
}

// checkCall fails unless c carries exactly the tier's system prompt and
// s.Text as the only user turn, with s's redaction counts.
func checkCall(t *testing.T, c gateway.Call, tier Tier, s Slice) {
	t.Helper()
	system, err := System(tier)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Messages []struct{ Role, Content string } `json:"messages"`
	}
	if err := json.Unmarshal(c.Payload, &body); err != nil {
		t.Fatalf("payload: %v", err)
	}
	m := body.Messages
	if len(m) != 2 || m[0].Role != "system" || m[0].Content != system || m[1].Role != "user" || m[1].Content != s.Text {
		t.Fatalf("messages = %+v, want the %s system prompt and Slice.Text as the user turn", m, tier)
	}
	if c.Purpose != "reader" || !maps.Equal(c.Redactions, s.Redactions) {
		t.Fatalf("call = purpose %q, redactions %v", c.Purpose, c.Redactions)
	}
}
