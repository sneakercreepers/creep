package reader

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// Evaluate sends the tier's system prompt and the slice with its redaction
// counts, so egress.log can account for them, and refuses an unknown tier
// before any call.
func TestEvaluateCall(t *testing.T) {
	slice := Slice{
		Hypothesis: 3,
		Text:       "HYPOTHESIS: sql_injection, source line 1, sink line 2\nCODE:\n1| def f():\n2|     run([REDACTED:password:1])\n",
		Shown:      []LineRange{{Start: 1, End: 2}},
		Redactions: map[string]int{"password": 1},
	}
	vulnerable := appHypothesis{variant: variantVulnerable, sink: 2}
	tests := []struct {
		name string
		tier Tier
		want error
	}{
		{"tier M", TierM, nil},
		{"tier S", TierS, nil},
		{"unknown tier", Tier("XL"), ErrTier},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []gateway.Call
			client, err := replayClient(func(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
				calls = append(calls, c)
				body, err := synthesizedReply(vulnerable)
				return &gateway.Reply{Status: 200, Body: body}, err
			})
			if err != nil {
				t.Fatal(err)
			}
			sig, err := Evaluate(context.Background(), client, tt.tier, slice)
			if tt.want != nil {
				if !errors.Is(err, tt.want) || len(calls) != 0 {
					t.Fatalf("err = %v after %d calls, want %v before any", err, len(calls), tt.want)
				}
				return
			}
			if err != nil || sig.Hypothesis != 3 || sig.Verdict != VerdictVulnerable {
				t.Fatalf("Evaluate = %+v, %v", sig, err)
			}
			if len(calls) != 1 {
				t.Fatalf("%d calls, want 1", len(calls))
			}
			system, _ := System(tt.tier)
			c := calls[0]
			if c.Purpose != "reader" || !maps.Equal(c.Redactions, slice.Redactions) ||
				!strings.Contains(string(c.Payload), firstLine(system)) {
				t.Fatalf("call = purpose %q, redactions %v", c.Purpose, c.Redactions)
			}
		})
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
