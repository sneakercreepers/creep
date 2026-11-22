package reader

import (
	_ "embed" // the system prompts are versioned data in prompts/
	"errors"
	"fmt"
)

// PromptVersion names the prompts in prompts/ and the answer schema. A
// change to either bumps it, so a recorded verdict says what produced it.
const PromptVersion = 2

// HintVersion names prompts/hint.txt, the note a slice with a recipe hint
// adds to the system prompt (ADR 0025). It is versioned apart, so hint-free
// calls, and every recording of them, keep PromptVersion.
const HintVersion = 1

// Tier selects the prompt variant. It mirrors calibrate.Tier, which reader
// may not import (both are layer 4); the caller converts with Tier(t).
type Tier string

const (
	TierS Tier = "S"
	TierM Tier = "M"
	TierL Tier = "L"
)

// ErrTier means a tier has no prompt, or Evaluate got a slice cut for
// another tier. There is no fallback, so a typo in the caller fails instead
// of silently using another variant.
var ErrTier = errors.New("reader: unknown tier")

var (
	//go:embed prompts/s.txt
	systemS string
	//go:embed prompts/m.txt
	systemM string
	//go:embed prompts/l.txt
	systemL string
	//go:embed prompts/hint.txt
	hintNote string
)

// promptBudget is the most tokens each tier's system prompt plus the output
// schema may take. Smaller tiers get less, because their context is
// smaller. Raising a budget is a reviewed change to this table.
var promptBudget = map[Tier]int{
	TierS: 1900,
	TierM: 2100,
	TierL: 2700,
}

// System returns the system prompt for tier.
func System(tier Tier) (string, error) {
	switch tier {
	case TierS:
		return systemS, nil
	case TierM:
		return systemM, nil
	case TierL:
		return systemL, nil
	}
	return "", fmt.Errorf("%w %q", ErrTier, string(tier))
}

// hintNoteBudget is the most tokens the hint note adds to a hinted call's
// system prompt. Only `creep recipe test` sends hinted slices; CallTokens,
// which the scan plans with, covers hint-free calls, and the gateway still
// enforces real spend on both.
const hintNoteBudget = 450

// systemFor is System, followed by the hint note when the slice has a HINT
// block, so a model is told the hint is data before it reads one.
func systemFor(tier Tier, hinted bool) (string, error) {
	system, err := System(tier)
	if err != nil || !hinted {
		return system, err
	}
	return system + "\n" + hintNote, nil
}

// CallTokens is the most input one reader call can take at tier: the system
// prompt with the schema (promptBudget) and the user turn (sliceBudget),
// counted as bytes like both budgets. The scan adds the reply's max_tokens
// to get planner.Budget.StepTokens; the gateway still enforces real spend.
func CallTokens(tier Tier) (int, error) {
	prompt, okPrompt := promptBudget[tier]
	slice, okSlice := sliceBudget[tier]
	if !okPrompt || !okSlice {
		return 0, fmt.Errorf("%w %q", ErrTier, string(tier))
	}
	return prompt + slice, nil
}
