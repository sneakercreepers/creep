package cli

import (
	"context"
	"errors"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/state"
)

// Assumptions estimate prints with its numbers (ADR 0010).
const (
	// bytesPerTenTokens converts request bytes to tokens: 4.5 bytes per
	// token. Prose and code run near 4 in current tokenizers, and a request
	// body adds JSON escapes the model never sees as tokens. The gateway
	// still reserves one token per byte, an upper bound.
	bytesPerTenTokens = 45
	// replyEstimateTokens is a typical reader or calibration answer: a
	// short closed-schema JSON object, far below max_tokens.
	replyEstimateTokens = 40
	// callSeconds is a typical round trip of one call. The scan makes one
	// call at a time, so time is calls times this.
	callSeconds = 5
)

// errNoModelCall is what every estimate request returns instead of a reply
// from a model: the send function it reaches has no transport at all.
var errNoModelCall = errors.New("estimate makes no model calls")

// requestMeasure adds up the requests a scan would make.
type requestMeasure struct {
	calls   int // requests the scan would make
	cached  int // of those, recorded in .creep/cache: served without the model
	inBytes int // request bytes of the uncached ones
	reserve int // tokens the gateway reserves for the uncached ones
}

func (r requestMeasure) live() int { return r.calls - r.cached }

func (r requestMeasure) inputTokens() int {
	return (r.inBytes*10 + bytesPerTenTokens - 1) / bytesPerTenTokens
}

func (r requestMeasure) outputTokens() int { return r.live() * replyEstimateTokens }

func (r requestMeasure) duration() time.Duration {
	return time.Duration(r.live()) * callSeconds * time.Second
}

func (r requestMeasure) plus(o requestMeasure) requestMeasure {
	return requestMeasure{calls: r.calls + o.calls, cached: r.cached + o.cached, inBytes: r.inBytes + o.inBytes, reserve: r.reserve + o.reserve}
}

// meter is a models.SendFunc that measures each request and never sends
// it: it holds no client, no dialer and no gateway link.
type meter struct {
	requestMeasure
	cache *state.Store   // run-state cache for lookups, or nil
	reply *gateway.Reply // canned reply; nil fails every request
}

func (m *meter) send(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
	m.calls++
	if m.recorded(c) {
		m.cached++
	} else {
		m.inBytes += len(c.Payload)
		m.reserve += c.ReserveTokens
	}
	if m.reply == nil {
		return nil, errNoModelCall
	}
	return m.reply, nil
}

// recorded reports whether a default scan would serve c from .creep/cache.
// The key is the scan's own (cacheKey over the exact body), so only the
// same request on the same model counts.
func (m *meter) recorded(c gateway.Call) bool {
	if m.cache == nil {
		return false
	}
	_, ok, err := m.cache.Lookup(cacheKey(c))
	return err == nil && ok
}

// readerRequests sends each slice through Evaluate to the meter, so the
// bodies are the reader's own, byte for byte.
func (m *meter) readerRequests(ctx context.Context, cfg config.Model, tier reader.Tier, slices []reader.Slice) error {
	model, err := measureModel(cfg, m.send)
	if err != nil {
		return err
	}
	for _, s := range slices {
		if _, err := reader.Evaluate(ctx, model, tier, s); err != nil && !errors.Is(err, errNoModelCall) {
			return err
		}
	}
	return nil
}

// measureModel is the scan's model client with send in place of the
// gateway and no key. A contract with no HTTP wire yet (command, #6) is
// measured as openai: the body is the same prompt, schema and slice.
func measureModel(m config.Model, send models.SendFunc) (*models.HTTP, error) {
	if m.Contract != "anthropic" {
		m.Contract = "openai"
	}
	if m.Endpoint == "" {
		m.Endpoint = "http://estimate.invalid"
	}
	if m.Name == "" {
		m.Name = "model"
	}
	opts := modelOptions(m, models.Key{}, send)
	opts.Retries = 0 // measure the first attempt; a retry is the model's doing
	return models.NewHTTP(opts)
}

// calibrationEstimate is whether the scan has to calibrate first.
type calibrationEstimate struct {
	cached   bool
	tier     calibrate.Tier
	requests requestMeasure // when not cached: at least these requests
}

func (est *estimateRun) calibration(ctx context.Context, deps scanDeps) (calibrationEstimate, error) {
	c, ok, err := est.cachedCalibration(ctx, deps)
	if err != nil || ok {
		return c, err
	}
	return est.measureCalibration(ctx)
}

// cachedCalibration looks the model's calibration up in the user cache, as
// scan does, with a model that cannot send: a miss ends in errNoModelCall.
func (est *estimateRun) cachedCalibration(ctx context.Context, deps scanDeps) (calibrationEstimate, bool, error) {
	m := est.cfg.Model
	if est.opts.recalibrate || checkModelConfig(m) != nil || est.cfg.Calibration.CacheDays <= 0 {
		return calibrationEstimate{}, false, nil
	}
	red, err := redact.New()
	if err != nil {
		return calibrationEstimate{}, false, err
	}
	model, err := measureModel(m, (&meter{}).send)
	if err != nil {
		return calibrationEstimate{}, false, err
	}
	cal, err := deps.calibrate(ctx, calibrate.CacheOptions{
		Options: calibrate.Options{Seed: calibrationSeed, Model: model, Redactor: red},
		MaxAge:  time.Duration(est.cfg.Calibration.CacheDays) * 24 * time.Hour,
	})
	switch {
	case errors.Is(err, errNoModelCall):
		return calibrationEstimate{}, false, nil
	case err != nil:
		return calibrationEstimate{}, false, err
	}
	return calibrationEstimate{cached: true, tier: cal.Tier}, true, nil
}

// unparsedAnswer is an OpenAI-compatible reply whose answer fails every
// calibration schema: calibration counts it as invalid and goes on, so one
// pass meters every task and probe without a model.
var unparsedAnswer = []byte(`{"id":"estimate","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}]}`)

// measureCalibration runs calibration against the meter. It is a lower
// bound: a model that passes the first context probe is sent larger ones.
// Nothing is stored; the result is thrown away.
func (est *estimateRun) measureCalibration(ctx context.Context) (calibrationEstimate, error) {
	red, err := redact.New()
	if err != nil {
		return calibrationEstimate{}, err
	}
	m := &meter{cache: est.cache, reply: &gateway.Reply{ID: "estimate", Status: 200, Body: unparsedAnswer}}
	cfg := est.cfg.Model
	cfg.Contract = "openai" // the canned reply is in this wire format
	model, err := measureModel(cfg, m.send)
	if err != nil {
		return calibrationEstimate{}, err
	}
	_, _ = calibrate.Run(ctx, calibrate.Options{Seed: calibrationSeed, Model: model, Redactor: red})
	return calibrationEstimate{requests: m.requestMeasure}, ctx.Err()
}
