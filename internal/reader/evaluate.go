package reader

import (
	"context"
	"fmt"

	"github.com/sneakercreepers/creep/internal/models"
)

// purpose labels reader calls in egress.log.
const purpose = "reader"

// Evaluate asks h's model whether s's hypothesis holds and projects the
// answer to a Signal. The user turn is s.Text, built from redact.File output
// only, and the call goes through h, whose SendFunc is the gateway in
// production, so redaction counts reach egress.log. tier must be the tier s
// was built for. An answer that fails the schema, Validate or Project is an
// error, never a verdict.
func Evaluate(ctx context.Context, h *models.HTTP, tier Tier, s Slice) (Signal, error) {
	system, err := System(tier)
	if err != nil {
		return Signal{}, err
	}
	a, err := models.Complete[Answer](ctx, h, models.Request{
		Purpose:    purpose,
		System:     system,
		Prompt:     s.Text,
		Redactions: s.Redactions,
		Schema:     Schema(),
		Grammar:    Grammar(),
	})
	if err != nil {
		return Signal{}, fmt.Errorf("reader: hypothesis %d: %w", s.Hypothesis, err)
	}
	return Project(s.Hypothesis, a, s.Shown)
}
