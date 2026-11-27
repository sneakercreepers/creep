package discover

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/models"
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
		// The example reply lists keys in the schema's order (#362).
		`{"file":<n>,"start":<line>,"end":<line>,"kind":"<kind>"}`,
		`{"file":<n>,"line":<line>,"kind":"<kind>","entry":<index or -1>}`,
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
		asked := "at most " + strconv.Itoa(itemsPerFile[tier]) + " items per file"
		for _, w := range append(words, asked) {
			if !strings.Contains(system, w) {
				t.Errorf("tier %s prompt does not mention %s", tier, w)
			}
		}
	}
}

// Acceptance (#362): a discovery reply cap holds every item the prompt
// asks for in every file of the batch, the canary included, grows with the
// batch, never exceeds maxReplyTokens and is larger than a reader reply
// (1024), so an honest full answer is not cut off.
func TestReplyTokens(t *testing.T) {
	for _, tier := range tiers {
		prev := 0
		for files := 1; files <= maxFiles; files++ {
			got, err := ReplyTokens(tier, files)
			if err != nil {
				t.Fatal(err)
			}
			need := files*itemsPerFile[tier]*itemTokens + replyFrameTokens
			if got < need || got > maxReplyTokens || got < prev {
				t.Errorf("tier %s, %d files: cap %d, need %d, max %d, smaller batch %d", tier, files, got, need, maxReplyTokens, prev)
			}
			prev = got
		}
		if prev <= 1024 {
			t.Errorf("tier %s full batch cap %d is not above the reader's 1024", tier, prev)
		}
		if over, _ := ReplyTokens(tier, maxFiles+5); over != prev {
			t.Errorf("tier %s: %d files over the batch get cap %d, want the full batch's %d", tier, maxFiles+5, over, prev)
		}
	}
	if _, err := ReplyTokens("XL", 1); !errors.Is(err, ErrTier) {
		t.Errorf("ReplyTokens(XL) = %v, want ErrTier", err)
	}
	if len(itemsPerFile) != len(tiers) {
		t.Errorf("itemsPerFile covers %d tiers, want %d", len(itemsPerFile), len(tiers))
	}
}

// Acceptance (#362): no schema creep sends lists "end" before "start" or
// any property out of reasoning order; the check fails on the
// alphabetical order json.Marshal gives a Go map.
func TestSchemaPropertyOrder(t *testing.T) {
	schema := Schema()
	if err := models.CheckPropertyOrder(schema); err != nil {
		t.Fatalf("discover schema: %v", err)
	}
	// CheckPropertyOrder ties each object's properties to its required
	// array, so these pin the reasoning order itself.
	for _, order := range []string{
		`"required":["entries","sinks","auth"]`, `"required":["file","start","end","kind"]`,
		`"required":["file","line","kind","entry"]`, `"required":["file","start","end"]`,
	} {
		if !strings.Contains(string(schema), order) {
			t.Errorf("schema lacks %s", order)
		}
	}
	alphabetical, err := json.Marshal(map[string]any{
		"type": "object", "properties": map[string]any{"file": 0, "start": 0, "end": 0, "kind": 0},
		"required": []string{"file", "start", "end", "kind"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(models.CheckPropertyOrder(alphabetical), models.ErrPropertyOrder) {
		t.Error("an alphabetical schema passed the order check")
	}
}

func TestSystemRejectsUnknownTier(t *testing.T) {
	for _, tier := range []Tier{"", "s", "XL", "S "} {
		if _, err := System(tier); !errors.Is(err, ErrTier) {
			t.Errorf("System(%q) = %v, want ErrTier", tier, err)
		}
	}
}
