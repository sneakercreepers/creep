package discover

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

var tiers = []Tier{TierS, TierM, TierL}

// TestPromptTokenBudget fails when a tier's system prompt plus the schema
// sent with it grows past its budget. Bytes bound tokens from above.
func TestPromptTokenBudget(t *testing.T) {
	for _, tier := range tiers {
		system, err := System(tier)
		if err != nil {
			t.Fatal(err)
		}
		budget, ok := promptBudget[tier]
		if !ok {
			t.Fatalf("tier %s has no token budget", tier)
		}
		used := len(system) + len(Schema())
		t.Logf("tier %s: prompt and schema take %d of %d", tier, used, budget)
		if used > budget {
			t.Errorf("tier %s prompt and schema take %d tokens, budget %d", tier, used, budget)
		}
	}
	if len(promptBudget) != len(tiers) || len(batchBudget) != len(tiers) {
		t.Errorf("budgets cover %d and %d tiers, want %d", len(promptBudget), len(batchBudget), len(tiers))
	}
}

// TestCallTokenBudget fails when a whole discovery call can grow past its
// tier's budget: system prompt, schema and the largest user turn a run
// builds, measured by filling a batch to the brim. Smaller tiers never get
// a larger call than bigger ones.
func TestCallTokenBudget(t *testing.T) {
	callBudget := map[Tier]int{TierS: 12 << 10, TierM: 37 << 10, TierL: 135 << 10}
	prev := 0
	for _, tier := range tiers {
		largest := largestPrompt(t, tier)
		if largest > batchBudget[tier] {
			t.Errorf("tier %s user turn takes %d tokens, budget %d", tier, largest, batchBudget[tier])
		}
		call, err := CallTokens(tier)
		if err != nil {
			t.Fatal(err)
		}
		if call > callBudget[tier] || call < prev {
			t.Errorf("tier %s call takes up to %d tokens, budget %d, smaller tier %d", tier, call, callBudget[tier], prev)
		}
		prev = call
	}
	if _, err := CallTokens("XL"); !errors.Is(err, ErrTier) {
		t.Errorf("CallTokens(XL) = %v, want ErrTier", err)
	}
}

// largestPrompt runs files sized to fill one batch and returns the
// longest user turn sent.
func largestPrompt(t *testing.T, tier Tier) int {
	t.Helper()
	files := map[string]string{}
	var paths []string
	line := strings.Repeat("y", 70) + "\n"
	per := (batchBudget[tier] - canarySize()) / MaxFilesPerBatch / (len(line) + 6)
	for i := range MaxFilesPerBatch {
		p := "f" + strconv.Itoa(i) + ".py"
		files[p] = strings.Repeat(line, per)
		paths = append(paths, p)
	}
	var prompts []string
	if _, err := runPaths(t, tier, paths, files, honestReply, &prompts); err != nil {
		t.Fatal(err)
	}
	if len(prompts) != 1 {
		t.Fatalf("tier %s: %d calls, want one full batch", tier, len(prompts))
	}
	return len(prompts[0])
}

// TestPromptsMatchSchema keeps every variant describing the reply the
// schema accepts, so editing one tier cannot drift from the decoder.
func TestPromptsMatchSchema(t *testing.T) {
	words := []string{
		`"file"`, `"entries"`, `"sinks"`, `"auth"`, `"start"`, `"end"`,
		`"kind"`, `"line"`, `"entry"`, "-1", "untrusted data", "nothing else",
		"at most 256 entries, 1024 sinks and 256 auth spans",
	}
	for _, k := range sinkKinds {
		words = append(words, `"`+k.name+`"`)
	}
	for _, k := range entryKindNames {
		words = append(words, `"`+k+`"`)
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
	if MaxEntriesPerFile != 256 || MaxSinksPerFile != 1024 || MaxAuthPerFile != 256 {
		t.Error("the prompts state caps the constants no longer have")
	}
}

func TestSystemRejectsUnknownTier(t *testing.T) {
	for _, tier := range []Tier{"", "s", "XL", "S "} {
		if _, err := System(tier); !errors.Is(err, ErrTier) {
			t.Errorf("System(%q) = %v, want ErrTier", tier, err)
		}
	}
}
