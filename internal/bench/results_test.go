package bench

import (
	"strings"
	"testing"
)

// A recorded model name cannot break the published Markdown, and a rate
// over nothing prints as none, never as 0 or 1.
func TestMarkdownStaysPlain(t *testing.T) {
	r := Results{
		Model: ModelInfo{Contract: "openai", Name: "evil|name`\n# heading"},
		Tiers: []TierResult{{Tier: "S", Classes: []ClassResult{{Class: "idor", Vulnerable: 1}}}},
		Smoke: SmokeRuns(),
	}
	md := r.Markdown()
	if strings.Contains(md, "evil|") || strings.Contains(md, "\n# heading") || !strings.Contains(md, "`evilnameheading`") {
		t.Fatalf("model name not made plain:\n%s", md)
	}
	if !strings.Contains(md, "| idor | 0/1 (none) | 0/0 (none) | 0/0 (none) | 0 |") {
		t.Fatalf("unmeasured rates:\n%s", md)
	}
	for _, s := range r.Smoke {
		if s.Status != "skipped" || !strings.Contains(md, s.Target+": skipped") {
			t.Fatalf("smoke run %+v missing or not skipped:\n%s", s, md)
		}
	}
}
