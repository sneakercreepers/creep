package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/planner"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/recipe"
)

// checkRecipes loads every installed recipe through recipe.Checker.Load at
// the calibrated tier, after creep.lock verified its bytes (ADR 0028): a
// recipe whose fixtures fail is refused and fails the scan (exit 2), a
// model failure exits as the model's, and none is skipped, so a scan never
// runs with fewer recipes than the lock lists.
func (s *session) checkRecipes(ctx context.Context, tier calibrate.Tier, stderr io.Writer) error {
	if len(s.installed) == 0 {
		return nil
	}
	rtier, err := readerTier(tier)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "recipes: checking the fixtures of %d installed recipe files from ~/%s/%s, redacted, with the model before the scan uses their hints\n", len(s.installed), recipeStore, recipe.LockFile)
	checker := recipe.Checker{Model: s.model, Redactor: s.red, Tier: rtier}
	for _, in := range s.installed {
		r, _, err := checker.Load(ctx, in.data, checkRecipePoC)
		if err != nil {
			return fmt.Errorf("installed recipe %s from %s: %w", in.pin.File, in.pin.Source, err)
		}
		s.recipes = append(s.recipes, r)
	}
	return nil
}

// hintedBudget adds the hint note to each step's cost when recipes may add
// a HINT block, once per --stability sample, so the planner never plans
// more hinted calls than the budget pays for. A zero step stays zero
// (planner.Build refuses it).
func hintedBudget(b planner.Budget, hinted bool, samples int) planner.Budget {
	if !hinted || b.StepTokens == 0 {
		return b
	}
	b.StepTokens += uint32(reader.HintNoteTokens * min(max(samples, 1), maxStability)) //nolint:gosec // G115: 450 times at most maxStability
	return b
}
