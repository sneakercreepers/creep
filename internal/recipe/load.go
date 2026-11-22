package recipe

import (
	"context"
	"errors"
	"fmt"

	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/redact"
)

// ErrFixtures means the model did not get the recipe's own fixtures right:
// the vulnerable one was not flagged, or the safe one was not clean. The
// recipe is refused.
var ErrFixtures = errors.New("recipe fixtures failed")

// Checker runs a recipe's fixtures through the quarantined reader: the
// run's model client (the gateway in production), its redactor and the
// calibrated tier.
type Checker struct {
	Model    *models.HTTP
	Redactor *redact.Redactor
	Tier     reader.Tier
}

// Outcome is what the fixtures got: reader Signals only, so nothing that
// carries recipe or model text leaves a check.
type Outcome struct {
	Vulnerable reader.Signal
	Safe       reader.Signal
}

// Fixture hypotheses and the names the slicer reads them by.
const (
	vulnerableID   reader.HypothesisID = 1
	safeID         reader.HypothesisID = 2
	vulnerablePath                     = "fixtures/vulnerable"
	safePath                           = "fixtures/safe"
)

// Load parses data and runs its fixtures: the only way to get a recipe
// creep may use. It is refused (ErrInvalid) before any model call when
// Parse refuses it, and (ErrFixtures) when the vulnerable fixture is not
// flagged or the safe one is not clean. A model or gateway failure is
// returned as it is, never read as a verdict.
func (c Checker) Load(ctx context.Context, data []byte, check PoCCheck) (*Recipe, Outcome, error) {
	r, err := Parse(data, check)
	if err != nil {
		return nil, Outcome{}, err
	}
	out, err := c.Check(ctx, r)
	if err != nil {
		return nil, out, err
	}
	return r, out, nil
}

// Check asks the reader about each fixture, with the recipe's hint, and
// judges the answers. A verdict from a cut slice is never a pass: a clean
// safe fixture must have been read whole.
func (c Checker) Check(ctx context.Context, r *Recipe) (Outcome, error) {
	if c.Model == nil || c.Redactor == nil {
		return Outcome{}, errors.New("recipe: Checker needs Model and Redactor")
	}
	cut, err := c.slices(r)
	if err != nil {
		return Outcome{}, err
	}
	var out Outcome
	if out.Vulnerable, err = reader.Evaluate(ctx, c.Model, c.Tier, cut[0]); err != nil {
		return out, fmt.Errorf("recipe: vulnerable fixture: %w", err)
	}
	if out.Safe, err = reader.Evaluate(ctx, c.Model, c.Tier, cut[1]); err != nil {
		return out, fmt.Errorf("recipe: safe fixture: %w", err)
	}
	return out, out.judge()
}

// slices cuts the two fixture slices, vulnerable first. A fixture the
// slicer cannot cut fails the recipe, never the run.
func (c Checker) slices(r *Recipe) ([]reader.Slice, error) {
	code := map[string]string{vulnerablePath: r.Fixtures.Vulnerable.Code, safePath: r.Fixtures.Safe.Code}
	class := classes[r.Class]
	targets := []reader.Target{
		{Hypothesis: vulnerableID, Class: class, Path: vulnerablePath, SourceLine: r.Fixtures.Vulnerable.SourceLine, SinkLine: r.Fixtures.Vulnerable.SinkLine, Hint: r.Hint},
		{Hypothesis: safeID, Class: class, Path: safePath, SourceLine: r.Fixtures.Safe.SourceLine, SinkLine: r.Fixtures.Safe.SinkLine, Hint: r.Hint},
	}
	read := func(p string) ([]byte, error) { return []byte(code[p]), nil }
	rep, err := reader.Slicer{Redactor: c.Redactor, Tier: c.Tier, Read: read}.Build(targets)
	if err != nil {
		return nil, fmt.Errorf("recipe: %w", err)
	}
	if len(rep.Slices) != len(targets) {
		return nil, fmt.Errorf("%w: a fixture could not be sliced (%s)", ErrFixtures, notEvaluated(rep))
	}
	return rep.Slices, nil
}

// notEvaluated names the closed reasons a fixture got no slice.
func notEvaluated(rep reader.SliceReport) string {
	if len(rep.NotEvaluated) == 0 {
		return "no reason"
	}
	return string(rep.NotEvaluated[0].Reason)
}

// judge passes only a vulnerable verdict on the vulnerable fixture and a
// not_vulnerable verdict on the safe one, each on a whole slice.
func (o Outcome) judge() error {
	switch {
	case o.Vulnerable.Verdict != reader.VerdictVulnerable:
		return fmt.Errorf("%w: the vulnerable fixture was not flagged (%s)", ErrFixtures, verdictName(o.Vulnerable.Verdict))
	case o.Safe.Verdict != reader.VerdictNotVulnerable:
		return fmt.Errorf("%w: the safe fixture was not clean (%s)", ErrFixtures, verdictName(o.Safe.Verdict))
	case o.Vulnerable.Partial || o.Safe.Partial:
		return fmt.Errorf("%w: a fixture does not fit the tier's slice whole; shorten it", ErrFixtures)
	}
	return nil
}

// verdictName is the closed name of a verdict, for messages.
func verdictName(v reader.Verdict) string {
	switch v {
	case reader.VerdictVulnerable:
		return "vulnerable"
	case reader.VerdictNotVulnerable:
		return "not_vulnerable"
	case reader.VerdictInconclusive:
		return "inconclusive"
	}
	return "no verdict"
}
