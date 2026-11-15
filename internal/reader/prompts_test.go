package reader

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

var tiers = []Tier{TierS, TierM, TierL}

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
