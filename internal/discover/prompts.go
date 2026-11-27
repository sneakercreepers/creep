package discover

import (
	_ "embed" // the system prompts are versioned data in prompts/
	"errors"
	"fmt"
)

// PromptVersion names the prompts in prompts/, the answer schema, the
// canary template and the batch layout. A change to any bumps it, so a
// recorded reply says what produced it.
const PromptVersion = 3

// Tier selects the prompt variant and the batch budget. It mirrors
// calibrate.Tier, which discover may not import (both are layer 4).
type Tier string

// Tiers.
const (
	TierS Tier = "S"
	TierM Tier = "M"
	TierL Tier = "L"
)

// ErrTier means a tier with no prompt. There is no fallback.
var ErrTier = errors.New("discover: unknown tier")

var (
	//go:embed prompts/s.txt
	systemS string
	//go:embed prompts/m.txt
	systemM string
	//go:embed prompts/l.txt
	systemL string
)

// promptBudget is the most tokens each tier's system prompt plus the
// output schema may take, counted as bytes (an upper bound on tokens, as
// in models). Raising one is a reviewed change; prompts_test.go holds it.
var promptBudget = map[Tier]int{
	TierS: 2900,
	TierM: 3800,
	TierL: 4700,
}

// batchBudget is the most bytes each tier's user turn may take: every
// section's header and numbered, escaped lines, the canary included. A
// whole file that does not fit alone is too_large (ADR 0017 D1): files are
// never split. Smaller tiers get less, because their context is smaller.
var batchBudget = map[Tier]int{
	TierS: 8 << 10,
	TierM: 32 << 10,
	TierL: 128 << 10,
}

// itemsPerFile is how many proposals (entries, sinks and auth spans
// together) each tier's prompt asks for at most per file, the most
// dangerous first (#362). A file that gets this many is truncated, since
// the model may have stopped because it was asked to: never read_full.
var itemsPerFile = map[Tier]int{
	TierS: 12,
	TierM: 24,
	TierL: 24,
}

const (
	// itemTokens bounds the tokens of one proposal as the schema writes it,
	// {"file":8,"line":999999,"kind":"http_client","entry":2303}, with its
	// separator; JSON digits and keys take one token per few bytes.
	itemTokens = 32
	// replyFrameTokens bounds the reply's frame: braces, array keys, spaces.
	replyFrameTokens = 64
	// maxReplyTokens keeps every discovery reply cap at or under the output
	// limit of the models creep presets name, so no endpoint refuses it.
	maxReplyTokens = 8192
)

// ReplyTokens is the max_tokens of a discovery call at tier for a batch of
// files sections, the canary included: room for the items the prompt asks
// for in every file. It is larger than a reader reply and bounded by the
// batch, so a full answer is never cut off (#362).
func ReplyTokens(tier Tier, files int) (int, error) {
	items, ok := itemsPerFile[tier]
	if !ok {
		return 0, fmt.Errorf("%w %q", ErrTier, string(tier))
	}
	files = min(max(files, 1), maxFiles)
	return min(files*items*itemTokens+replyFrameTokens, maxReplyTokens), nil
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

// CallTokens is the most input one discovery call can take at tier: the
// system prompt with the schema and the user turn, counted as bytes. The
// caller adds the reply's max_tokens; the gateway enforces real spend.
func CallTokens(tier Tier) (int, error) {
	prompt, okPrompt := promptBudget[tier]
	batch, okBatch := batchBudget[tier]
	if !okPrompt || !okBatch {
		return 0, fmt.Errorf("%w %q", ErrTier, string(tier))
	}
	return prompt + batch, nil
}
