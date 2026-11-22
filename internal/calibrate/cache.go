package calibrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/state"
)

// CacheOptions configures RunCached.
type CacheOptions struct {
	Options // the run made when no cached result can be used
	// Store holds the cache, normally in the user's cache directory: a
	// calibration measures the model, not the scanned repository.
	Store *state.Store
	// MaxAge is how long a calibration stays valid (calibration.cache_days).
	MaxAge time.Duration
	// Recalibrate (--recalibrate) runs and stores a new calibration even when
	// a valid one is cached.
	Recalibrate bool
	// Now is the clock; tests inject one.
	Now func() time.Time
}

// Calibration is a Result with the model it measured and when.
type Calibration struct {
	Result
	Model models.Identity
	At    time.Time // when the calibration ran, UTC
	// Cached is true when the result came from the cache, not from a run.
	Cached bool
	// Stability is what earlier --stability scans of this model saw, per
	// class (ADR 0024); nil when none is recorded.
	Stability map[Class]ClassStability
}

// cacheKeyFields is everything a cached result depends on. A change to any
// of them is a different file, so a stale tier is never reused. Adding a
// field changes every key: entries stored under the old keys are never
// looked up again, so they are recalibrated over, not misread (#180).
type cacheKeyFields struct {
	Model         models.Identity `json:"model"`
	Client        models.Settings `json:"client"`
	Seed          uint64          `json:"seed"`
	TaskSet       string          `json:"task_set"`
	PromptVersion int             `json:"prompt_version"`
}

// RunCached returns the cached calibration for the model, seed, task set and
// PromptVersion when it is younger than MaxAge, and otherwise calls Run and
// stores the new result. A cached result is used only when it is
// authenticated, decodes strictly, matches the key and still gets the tier
// it records; anything else (corrupt, planted, expired, from the future) is
// ignored and replaced. A file written by a newer creep fails closed with
// state.ErrUnsupportedVersion unless Recalibrate replaces it.
func RunCached(ctx context.Context, opts CacheOptions) (Calibration, error) {
	if opts.Store == nil || opts.Now == nil || opts.MaxAge <= 0 || opts.Model == nil {
		return Calibration{}, fmt.Errorf("%w: store, clock, max age and model are required", ErrOptions)
	}
	tasks, err := Generate(opts.Seed)
	if err != nil {
		return Calibration{}, err
	}
	// A linked calibrations/ directory fails before any model call: no
	// result could be stored, and recalibrating cannot replace it.
	if err := opts.Store.CheckCalibrationDir(); err != nil {
		return Calibration{}, err
	}
	want := keyFields(opts, tasks)
	c, err := runCached(ctx, opts, tasks, want)
	if err != nil {
		return Calibration{}, err
	}
	// The stability record is a note on the calibration: one that cannot
	// be read is left out, never a reason to fail it (ADR 0024).
	c.Stability, _ = loadStability(opts, want)
	return c, nil
}

func runCached(ctx context.Context, opts CacheOptions, tasks []Task, want cacheKeyFields) (Calibration, error) {
	key := cacheKey(want)
	if !opts.Recalibrate {
		c, ok, err := loadCached(opts, key, want)
		if err != nil || ok {
			return c, err
		}
	}
	r, err := run(ctx, opts.Options, tasks)
	if err != nil {
		return Calibration{}, err
	}
	return store(opts, key, want, r)
}

// keyFields is what a calibration of opts measures, the key of its cache
// entry and of its stability record.
func keyFields(opts CacheOptions, tasks []Task) cacheKeyFields {
	return cacheKeyFields{
		Model: opts.Model.Identity(), Client: opts.Model.Settings(), Seed: opts.Seed,
		TaskSet: taskSetHash(tasks), PromptVersion: PromptVersion,
	}
}

func cacheKey(f cacheKeyFields) string {
	b, err := json.Marshal(f)
	if err != nil {
		panic(err) // strings and integers always marshal
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// loadCached returns a usable cached calibration, if there is one. Only a
// newer version or an I/O failure is an error; a file creep cannot trust is
// a miss.
func loadCached(opts CacheOptions, key string, want cacheKeyFields) (Calibration, bool, error) {
	c, ok, err := opts.Store.LoadCalibration(key)
	if err != nil && !untrusted(err) {
		return Calibration{}, false, fmt.Errorf("calibration cache: %w", err)
	}
	if err != nil || !ok {
		return Calibration{}, false, nil
	}
	age := opts.Now().Sub(c.At)
	if age < 0 || age >= opts.MaxAge {
		return Calibration{}, false, nil
	}
	r, ok := decodeCached(c.Result, want)
	if !ok {
		return Calibration{}, false, nil
	}
	return Calibration{Result: r, Model: want.Model, At: c.At.UTC(), Cached: true}, true, nil
}

// untrusted reports a cache file that is torn, planted, a link or otherwise
// not this user's creep's: it is recalibrated over, never read. A file of a
// newer version is not ErrCorrupt (its MAC is checked first, so it is this
// user's), and fails closed instead.
func untrusted(err error) bool {
	return errors.Is(err, state.ErrCorrupt) || errors.Is(err, state.ErrUnsafePath)
}

// decodeCached decodes a stored Result strictly and checks it describes
// the tasks and prompts asked for and still earns its tier under the
// current rules.
func decodeCached(raw json.RawMessage, want cacheKeyFields) (Result, bool) {
	var r Result
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || dec.More() {
		return Result{}, false
	}
	if r.Seed != want.Seed || r.TaskSet != want.TaskSet || r.PromptVersion != want.PromptVersion {
		return Result{}, false
	}
	if !r.Context.consistent() {
		return Result{}, false
	}
	return r, r.Tier == assignTier(r)
}

func store(opts CacheOptions, key string, want cacheKeyFields, r Result) (Calibration, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return Calibration{}, fmt.Errorf("calibration cache: %w", err)
	}
	at := opts.Now().UTC().Truncate(time.Second)
	if err := opts.Store.SaveCalibration(key, state.Calibration{At: at, Result: raw}); err != nil {
		return Calibration{}, fmt.Errorf("calibration cache: %w", err)
	}
	return Calibration{Result: r, Model: want.Model, At: at}, nil
}

// Header is the report's calibration line: model, tier, calibration date
// and what was measured, so two reports can be compared, then why the
// context probe stopped early, if it did. The model name is quoted because
// it comes from configuration.
func (c Calibration) Header() string {
	set := c.TaskSet
	if len(set) > 12 {
		set = set[:12]
	}
	return fmt.Sprintf("model %q · tier %s · calibrated %s (seed %d, task set %s, prompts v%d)%s%s",
		c.Model.Model, c.Tier, c.At.UTC().Format(time.DateOnly), c.Seed, set, c.PromptVersion,
		contextNote(c.Context), stabilityNote(c.Stability))
}

// contextNote says which context probe failed and why, so a model held at
// a low tier by a refusal unrelated to size (a 400 on the 8 KiB probe) is
// visible in the report.
func contextNote(c ContextCheck) string {
	if c.Stop == "" {
		return ""
	}
	reason := string(c.Stop)
	if c.Stop == ContextStopStatus {
		reason = fmt.Sprintf("HTTP %d", c.Status)
	}
	return fmt.Sprintf(" · context %d KiB (%d KiB probe: %s)", c.EffectiveBytes>>10, c.StoppedAt>>10, reason)
}
