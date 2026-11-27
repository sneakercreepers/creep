package discover

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/models"
)

// The doctor's discovery probe (#362) passes only a reply that a scan's
// batch would pass, and sends nothing but the canary: one FILE section of
// creep's own template, so no repository text can be in it.
func TestProbe(t *testing.T) {
	tests := []struct {
		name  string
		reply replyFunc
		want  error
	}{
		{"honest", answering(func(secs []promptSection) any { return honest(secs) }), nil},
		{"canary inside the window", answering(func(secs []promptSection) any {
			c, _ := canaryOf(secs)
			return Answer{Entries: []EntryProposal{entryAt(c.section, c.entry+1, c.entry+1, "http")},
				Sinks: []SinkProposal{sinkAt(c.section, c.sink-1, "file", -1)}, Auth: []AuthProposal{}}
		}), nil},
		{"canary missed", answering(func([]promptSection) any {
			return Answer{Entries: []EntryProposal{}, Sinks: []SinkProposal{}, Auth: []AuthProposal{}}
		}), ErrProbeCanary},
		{"line past the file", answering(func(secs []promptSection) any {
			c, _ := canaryOf(secs)
			return Answer{Entries: []EntryProposal{entryAt(c.section, 1, 50, "http")}, Sinks: []SinkProposal{}, Auth: []AuthProposal{}}
		}), ErrProbeBounds},
		{"schema broken", func([]promptSection) ([]byte, error) { return []byte(`{"entries":[{"end":2}]}`), nil }, models.ErrInvalidOutput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var prompts []string
			err := Probe(context.Background(), fakeClient(t, tt.reply, &prompts), TierS, testSeed)
			if !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
				t.Fatalf("Probe = %v, want %v", err, tt.want)
			}
			if len(prompts) != 1 {
				t.Fatalf("%d calls, want 1", len(prompts))
			}
			secs := parseSections(prompts[0])
			if _, ok := canaryOf(secs); !ok || len(secs) != 1 || strings.Count(prompts[0], "FILE ") != 1 {
				t.Errorf("probe prompt is not the canary alone:\n%s", prompts[0])
			}
		})
	}
	if err := Probe(context.Background(), fakeClient(t, nil, nil), "XL", testSeed); !errors.Is(err, ErrTier) {
		t.Errorf("Probe(XL) = %v, want ErrTier", err)
	}
}
