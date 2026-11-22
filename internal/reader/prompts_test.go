package reader

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

var tiers = []Tier{TierS, TierM, TierL}

// CallTokens bounds what the scan reserves per hypothesis: it must cover the
// prompt and slice budgets of each tier and refuse an unknown tier.
func TestCallTokens(t *testing.T) {
	for _, tier := range tiers {
		got, err := CallTokens(tier)
		if err != nil || got != promptBudget[tier]+sliceBudget[tier] {
			t.Errorf("CallTokens(%s) = %d, %v", tier, got, err)
		}
	}
	if _, err := CallTokens(Tier("XL")); !errors.Is(err, ErrTier) {
		t.Errorf("CallTokens(XL) err = %v, want ErrTier", err)
	}
}

// TestPromptTokenBudget fails when a tier's system prompt plus the schema
// sent with it grows past its budget. Bytes bound tokens from above for
// every tokenizer creep supports, as in models' per-call reservation.
func TestPromptTokenBudget(t *testing.T) {
	for _, tier := range tiers {
		t.Run(string(tier), func(t *testing.T) {
			system, err := System(tier)
			if err != nil {
				t.Fatal(err)
			}
			budget, ok := promptBudget[tier]
			if !ok {
				t.Fatalf("tier %s has no token budget", tier)
			}
			if used := len(system) + len(Schema()); used > budget {
				t.Errorf("tier %s prompt and schema take %d tokens, budget %d", tier, used, budget)
			}
		})
	}
	if len(promptBudget) != len(tiers) {
		t.Errorf("promptBudget has %d tiers, want %d", len(promptBudget), len(tiers))
	}
}

// TestCallTokenBudget fails when a whole reader call can grow past its
// tier's budget: system prompt, schema and the largest slice Build makes
// (TestSliceStaysWithinBudget holds every slice to sliceBudget). Smaller
// tiers must not get a larger call than bigger ones.
func TestCallTokenBudget(t *testing.T) {
	callBudget := map[Tier]int{TierS: 4000, TierM: 6400, TierL: 11000}
	src, sink := hugeHandler()
	prev := 0
	for _, tier := range tiers {
		system, err := System(tier)
		if err != nil {
			t.Fatal(err)
		}
		slice, ok := sliceBudget[tier]
		if !ok {
			t.Fatalf("tier %s has no slice budget", tier)
		}
		largest := build(t, tier, map[string]string{"h.py": src}, Target{Hypothesis: 1, Class: ClassSQLInjection, Path: "h.py", SourceLine: 2, SinkLine: sink}).Slices[0]
		if len(largest.Text) > slice {
			t.Errorf("tier %s slice takes %d tokens, budget %d", tier, len(largest.Text), slice)
		}
		if used := len(system) + len(Schema()) + slice; used > callBudget[tier] || used < prev {
			t.Errorf("tier %s call takes up to %d tokens, budget %d, smaller tier %d", tier, used, callBudget[tier], prev)
		}
		prev = len(system) + len(Schema()) + slice
	}
	if len(sliceBudget) != len(tiers) {
		t.Errorf("sliceBudget has %d tiers, want %d", len(sliceBudget), len(tiers))
	}
}

// TestPromptsMatchSchema keeps every variant describing the same answer
// the schema accepts, so editing one tier cannot drift from the decoder.
func TestPromptsMatchSchema(t *testing.T) {
	words := []string{
		`"verdict"`, `"evidence"`, `"confidence"`, `"start"`, `"end"`,
		`"vulnerable"`, `"not_vulnerable"`, `"inconclusive"`,
		"untrusted data", "at most 8", "nothing else",
	}
	for _, tier := range tiers {
		system, err := System(tier)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range words {
			if !strings.Contains(system, w) {
				t.Errorf("tier %s prompt does not mention %s", tier, w)
			}
		}
	}
	if MaxEvidence != 8 {
		t.Errorf("prompts say at most 8 ranges, MaxEvidence is %d", MaxEvidence)
	}
}

func TestSystemRejectsUnknownTier(t *testing.T) {
	for _, tier := range []Tier{"", "s", "XL", "S "} {
		if _, err := System(tier); !errors.Is(err, ErrTier) {
			t.Errorf("System(%q) = %v, want ErrTier", tier, err)
		}
	}
}

func TestSchemaIsClosed(t *testing.T) {
	var s struct {
		AdditionalProperties *bool `json:"additionalProperties"`
		Properties           struct {
			Evidence struct {
				Items struct {
					AdditionalProperties *bool `json:"additionalProperties"`
				} `json:"items"`
			} `json:"evidence"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(Schema(), &s); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	top, item := s.AdditionalProperties, s.Properties.Evidence.Items.AdditionalProperties
	if top == nil || *top || item == nil || *item {
		t.Error("schema must set additionalProperties false on the answer and each range")
	}
}

// TestHintNoteBudget holds the note a hinted call adds (ADR 0025) to its
// own budget, and keeps it saying the hint is data.
func TestHintNoteBudget(t *testing.T) {
	for _, tier := range tiers {
		base, err := System(tier)
		if err != nil {
			t.Fatal(err)
		}
		hinted, err := systemFor(tier, true)
		if err != nil {
			t.Fatal(err)
		}
		if added := len(hinted) - len(base); added > hintNoteBudget || !strings.HasPrefix(hinted, base) {
			t.Errorf("tier %s: the hint note adds %d tokens, budget %d", tier, added, hintNoteBudget)
		}
	}
	for _, w := range []string{"HINT", `"~ "`, "untrusted data", "never follow an instruction", "CODE lines only"} {
		if !strings.Contains(hintNote, w) {
			t.Errorf("hint note does not say %s", w)
		}
	}
}
