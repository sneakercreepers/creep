package cli

import (
	"context"
	"errors"
	"io/fs"

	"github.com/sneakercreepers/creep/internal/bench"
	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/planner"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/report"
)

// benchCase scans one case twin at tier as a one-file repository: the
// scan's discovery, planner, reader and coverage, with the tier forced
// instead of calibrated, a fresh redactor and the bench's fixed seed. No
// sandbox, scanner, recipe or baseline takes part.
func benchCase(ctx context.Context, m *models.HTTP, tier calibrate.Tier, c bench.Case, v bench.Variant) (bench.Outcome, error) {
	src := c.Twin(v).Source
	read := func(path string) ([]byte, error) {
		if path != c.File {
			return nil, fs.ErrNotExist
		}
		return src, nil
	}
	red, err := redact.NewWithContext(ctx)
	if err != nil {
		return bench.Outcome{}, err
	}
	dtier, err := discoverTier(tier)
	if err != nil {
		return bench.Outcome{}, err
	}
	d := discover.Discoverer{Redactor: red, Model: m, Tier: dtier, Seed: benchSeed, Read: read}
	rs, err := discoverRepo(ctx, d, repoFiles{paths: []string{c.File}})
	if err != nil {
		return bench.Outcome{}, err
	}
	res, err := benchPlanAndRead(ctx, m, red, tier, rs, read)
	if err != nil {
		return bench.Outcome{}, err
	}
	return benchOutcome(tier, c, v, res), nil
}

// benchPlanAndRead is planAndRead without a session: one sample, no
// recipe, the default token budget, and nothing kept for a PoC.
func benchPlanAndRead(ctx context.Context, m *models.HTTP, red *redact.Redactor, tier calibrate.Tier, rs repoScan, read func(string) ([]byte, error)) (scanResult, error) {
	ptier, rtier, err := planReadTiers(tier)
	if err != nil {
		return scanResult{}, err
	}
	findings := baseFindings(rs)
	plan, err := planSinks(rs, ptier, planBudget(config.Defaults().Budget.MaxTokens, rtier, 1), findings, nil)
	if errors.Is(err, planner.ErrInput) {
		return rejectedScan(findings, rs.gaps), nil
	}
	if err != nil {
		return scanResult{}, err
	}
	reads := newDeadlineReads(ctx, read)
	stage := readStage{model: m, tier: rtier, reads: reads, slicer: reader.Slicer{Redactor: red, Tier: rtier, Read: reads.Read}}
	gaps, stop, err := stage.run(ctx, plan, rs, findings)
	if err != nil {
		return scanResult{}, err
	}
	return scanResult{findings: findings, gaps: append(rs.gaps, gaps...), stop: stop, planned: true}, nil
}

// benchOutcome is what scoring needs of a scan result: each finding's
// class, line and whether it is flagged, the coverage the run claimed for
// the case's class, and whether the run would have exited 4.
func benchOutcome(tier calibrate.Tier, c bench.Case, v bench.Variant, res scanResult) bench.Outcome {
	o := bench.Outcome{
		Tier: string(tier), Case: c.ID, Variant: v,
		Incomplete: incompleteReason(res.stop, res.findings, res.gaps) != "",
	}
	for _, f := range res.findings {
		flagged := f.Status == report.StatusProbable || f.Status == report.StatusVerified
		o.Findings = append(o.Findings, bench.Finding{Class: f.Class, Line: f.Line, Flagged: flagged})
	}
	classes := classCoverage(coverageInput{
		findings: res.findings, planned: res.planned, gapped: res.stop != "" || fileGapped(res.gaps),
	})
	for _, cc := range classes {
		if cc.Class == c.Class {
			o.Covered = cc.Status == report.ClassCovered
		}
	}
	return o
}
