package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/redact"
)

// numCtxHint is the fix for the most common short context: Ollama's
// default num_ctx, which cuts long inputs silently (README, Ollama).
const numCtxHint = "with Ollama, create the model with num_ctx 16384 or more (see the README, Ollama)"

// doctorModel sends the model two synthetic probes, as a scan would send
// them and holding no repository text (ADR 0035): a discovery batch of
// only the canary, then a context probe the size of the tier's largest
// discovery call. The tier is the cached calibration's, or S when there is
// none; doctor never calibrates. A failed call is an error (exit 3); a
// reply that breaks the schema, misses the canary or loses the start of
// the context is a warning, since the scan itself says so with exit 4.
func doctorModel(ctx context.Context, e env, r *config.Resolved, link modelLink) error {
	opts, err := sessionModelOptions(r.Config.Model, link.command, link.send)
	if err != nil {
		return err
	}
	m, err := models.NewHTTP(opts)
	if err != nil {
		return err
	}
	red, err := redact.NewWithContext(ctx)
	if err != nil {
		return err
	}
	tier, calibrated := doctorTier(ctx, e, r, m, red)
	if err := doctorDiscovery(ctx, e, m, tier); err != nil {
		return err
	}
	return doctorContext(ctx, e, calibrate.Options{Seed: calibrationSeed, Model: m, Redactor: red}, tier, calibrated)
}

// doctorTier is the cached calibration's tier, read from the cache only.
func doctorTier(ctx context.Context, e env, r *config.Resolved, m *models.HTTP, red *redact.Redactor) (discover.Tier, bool) {
	cal, err := e.deps.calibrate(ctx, calibrate.CacheOptions{
		Options:   calibrate.Options{Seed: calibrationSeed, Model: m, Redactor: red},
		MaxAge:    time.Duration(r.Config.Calibration.CacheDays) * 24 * time.Hour,
		CacheOnly: true,
	})
	if err != nil {
		return discover.TierS, false
	}
	switch cal.Tier {
	case calibrate.TierM:
		return discover.TierM, true
	case calibrate.TierL:
		return discover.TierL, true
	}
	return discover.TierS, true
}

// doctorDiscovery runs discover.Probe and reports how it went.
func doctorDiscovery(ctx context.Context, e env, m *models.HTTP, tier discover.Tier) error {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return fmt.Errorf("probe seed: %w", err)
	}
	err := discover.Probe(ctx, m, tier, seed)
	var problem string
	switch {
	case err == nil:
		fmt.Fprintf(e.stdout, "model: reachable; a synthetic tier %s discovery batch (no repository text) came back inside the schema with its canary found\n", tier)
		return nil
	case errors.Is(err, models.ErrInvalidOutput):
		problem = "broke the discovery schema"
	case errors.Is(err, discover.ErrProbeBounds):
		problem = "cited lines the batch does not have"
	case errors.Is(err, discover.ErrProbeCanary):
		problem = "missed the discovery canary"
	default:
		return err
	}
	fmt.Fprintf(e.stdout, "warning: model: the reply to a synthetic tier %s discovery batch %s; a scan would list its files parse_failed and exit 4 (a larger model, or one that follows JSON schemas, may pass)\n", tier, problem)
	return nil
}

// doctorContext checks that the usable context holds the tier's largest
// discovery call.
func doctorContext(ctx context.Context, e env, opts calibrate.Options, tier discover.Tier, calibrated bool) error {
	need, err := discover.CallTokens(tier)
	if err != nil {
		return err
	}
	stop, err := calibrate.ContextFits(ctx, opts, need)
	if err != nil {
		return err
	}
	from := "calibrated tier"
	if !calibrated {
		from = "tier S until the first scan calibrates"
	}
	if stop == "" {
		fmt.Fprintf(e.stdout, "model: usable context holds the %d KiB a tier %s discovery call needs (%s)\n", need>>10, tier, from)
		return nil
	}
	fmt.Fprintf(e.stdout, "warning: model: usable context is below the %d KiB a tier %s discovery call needs (%s; probe: %s): the endpoint may cut long inputs and the system prompt with them; %s\n", need>>10, tier, from, stop, numCtxHint)
	return nil
}
