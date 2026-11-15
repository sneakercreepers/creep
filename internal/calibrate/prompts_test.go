package calibrate

import (
	"encoding/json"
	"slices"
	"testing"
)

// budgetSeeds are the seeds whose tasks the budget test measures. Task size
// depends on the seed only through padding and identifier choice, so a
// range of seeds finds the largest prompt the templates can produce.
var budgetSeeds = []uint64{0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 0xdeadbeef, 1 << 63}

// TestPromptTokenBudget fails when a calibration call grows past its
// budget: the system prompt, the output schema and the largest user turn of
// its kind. Bytes bound tokens from above, as in models' reservation.
func TestPromptTokenBudget(t *testing.T) {
	tests := []struct {
		kind   string
		system string
		schema json.RawMessage
		user   int
	}{
		{purposeTask, taskSystem, taskSchema(), largestTaskTurn(t)},
		{purposeTool, toolsSystem, toolSchema(), largestToolTurn()},
		{purposeContext, contextSystem, contextSchema(), largestContextTurn()},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			budget, ok := promptBudget[tt.kind]
			if !ok {
				t.Fatalf("call kind %s has no token budget", tt.kind)
			}
			if used := len(tt.system) + len(tt.schema) + tt.user; used > budget {
				t.Errorf("%s calls take up to %d tokens, budget %d", tt.kind, used, budget)
			}
		})
	}
	if len(promptBudget) != len(tests) {
		t.Errorf("promptBudget has %d call kinds, want %d", len(promptBudget), len(tests))
	}
}

func largestTaskTurn(t *testing.T) int {
	t.Helper()
	largest := 0
	for _, seed := range budgetSeeds {
		for _, task := range mustGenerate(t, seed) {
			largest = max(largest, len(numberLines(task.Code)))
		}
	}
	return largest
}

func largestToolTurn() int {
	largest := 0
	for _, seed := range budgetSeeds {
		for _, p := range toolProbes(probeSource(seed)) {
			largest = max(largest, len(p.prompt))
		}
	}
	return largest
}

func largestContextTurn() int {
	size := slices.Max(contextSizes)
	largest := 0
	for _, seed := range budgetSeeds {
		largest = max(largest, len(newContextProbe(probeSource(seed), size).prompt))
	}
	return largest
}
