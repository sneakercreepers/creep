package cli

import (
	"context"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/redact"
)

// emptyDiscovery is an OpenAI-compatible reply that proposes nothing. The
// meter answers every discovery request with it, so discovery goes on to
// the next batch and every batch is built and measured; no model sees it.
var emptyDiscovery = []byte(`{"id":"estimate","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"{\"entries\":[],\"sinks\":[],\"auth\":[]}"},"finish_reason":"stop"}]}`)

// measureDiscovery runs discovery at tier against the meter: every batch
// the scan would send is built from the same redacted files, seed and
// prompt, and measured, never sent (ADR 0017 D1, ADR 0011 option B). The
// requests are measured in the OpenAI wire format, as calibration is, so
// the meter can answer them. red is the tier's redactor, shared with the
// reader stage as the scan shares it, so placeholders number alike and the
// slices match the scan's cached requests.
//
// The empty answers miss every canary. The estimate predicts what cannot
// be evaluated, not what the model will say, so a batch whose only fault
// is that is counted as read in full; the candidates are the tripwire's,
// the reader's floor (the model may propose more).
func (est *estimateRun) measureDiscovery(ctx context.Context, tier calibrate.Tier, red *redact.Redactor, t *tierEstimate) (repoScan, error) {
	dtier, err := discoverTier(tier)
	if err != nil {
		return repoScan{}, err
	}
	m := &meter{cache: est.cache, reply: &gateway.Reply{ID: "estimate", Status: 200, Body: emptyDiscovery}}
	cfg := est.cfg.Model
	cfg.Contract = "openai" // the canned reply is in this wire format
	model, err := measureModel(cfg, m.send)
	if err != nil {
		return repoScan{}, err
	}
	d := discover.Discoverer{Redactor: red, Model: model, Tier: dtier, Seed: est.seed, Read: readRepoFile(est.repo)}
	res, marks, err := runDiscovery(ctx, d, est.files)
	if err != nil {
		return repoScan{}, err
	}
	assumeCanaryFound(res.Files)
	rs := discoverRepoResult(res, est.files, marks)
	t.discovery, t.requests = m.requestMeasure, m.requestMeasure
	t.wholeFiles, t.candidates = rs.disc.WholeFiles, len(rs.res.Sinks)
	return rs, nil
}

// assumeCanaryFound counts a file whose batch missed the canary as read in
// full: here only because the meter's answer is empty.
func assumeCanaryFound(files []discover.File) {
	for i := range files {
		if files[i].Coverage == discover.CoverageCanaryMissed {
			files[i].Coverage, files[i].Reason = discover.CoverageReadFull, discover.ReasonNone
		}
	}
}
