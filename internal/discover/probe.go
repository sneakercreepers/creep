package discover

import (
	"context"
	"errors"

	"github.com/sneakercreepers/creep/internal/models"
)

// probePurpose labels the doctor's discovery probe in egress.log.
const probePurpose = "doctor.discover"

var (
	// ErrProbeBounds means the probe's reply cited a file or line the batch
	// does not have.
	ErrProbeBounds = errors.New("discovery probe: the reply cited lines the batch does not have")
	// ErrProbeCanary means the probe's reply missed the canary, as a scan's
	// batch would: every file of it would be parse_failed (exit 4).
	ErrProbeCanary = errors.New("discovery probe: the reply missed the canary")
)

// Probe sends one discovery call at tier whose batch holds only the canary,
// creep's own synthetic file, so no repository text leaves the machine. It
// returns nil when the model answered inside the schema and found the
// canary as a scan requires; models' errors for an unreachable endpoint or
// an invalid reply (*models.InvalidOutputError), or ErrProbeBounds or
// ErrProbeCanary. creep doctor runs it to tell, before any scan, whether
// discovery can pass with this model (#362).
func Probe(ctx context.Context, m *models.HTTP, tier Tier, seed [32]byte) error {
	system, err := System(tier)
	if err != nil {
		return err
	}
	batch, c, ok := plantCanary(seed, nil)
	if !ok {
		return ErrProbeCanary // an empty batch holds no token; unreachable
	}
	replyCap, _ := ReplyTokens(tier, len(batch)) // System checked the tier
	a, err := models.Complete[Answer](ctx, m, models.Request{
		Purpose: probePurpose, System: system, Prompt: renderBatch(batch),
		Schema: Schema(), Grammar: Grammar(), MaxOutputTokens: replyCap,
	})
	if err != nil {
		return err
	}
	rep, err := a.reply()
	if err != nil || !inBounds(rep, batch) {
		return ErrProbeBounds
	}
	if !c.found(rep) {
		return ErrProbeCanary
	}
	return nil
}
