package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/static"
)

// errScanDeadline is the run context's cause once budget.max_seconds has
// passed (#260).
var errScanDeadline = errors.New("scan deadline reached (budget.max_seconds)")

// reasonDeadline is what the deadline leaves behind, files and findings
// alike. Report v1 is frozen (ADR 0009, ADR 0017), so it reuses budget: the
// deadline is the run's time budget, and budget already ends a run
// incomplete.
const reasonDeadline = string(report.SkipBudget)

// scanWithin runs the repository scan and the optional scanners under the
// scan deadline. Calibration reads no repository text, so the deadline
// starts after it and a hostile repository cannot spend it there. Each stage
// lists what the deadline cut; a run it cut stops with reason budget and is
// never clean.
func (s *session) scanWithin(ctx context.Context, cancel context.CancelCauseFunc, tier calibrate.Tier, stderr io.Writer) (scanResult, error) {
	limit := time.Duration(s.cfg.Budget.MaxSeconds) * time.Second
	timer := time.AfterFunc(limit, func() { cancel(errScanDeadline) })
	res, err := s.scan(ctx, tier)
	if err == nil {
		res.scanners = runScanners(ctx, s.cfg.Scanners.Enabled, s.deps.scannerRunner(), stderr)
	}
	timer.Stop()
	if err != nil || !errors.Is(context.Cause(ctx), errScanDeadline) {
		return res, err
	}
	fmt.Fprintf(stderr, "creep scan: the scan deadline of %d s (budget.max_seconds) passed; the work left is listed as not evaluated (reason %s)\n", s.cfg.Budget.MaxSeconds, reasonDeadline)
	if res.stop == "" {
		res.stop = reasonDeadline
	}
	return res, nil
}

// walkFile extracts one source file with addRepoFile. Past the deadline a
// file is listed without being read, and a file the deadline cut while it
// was parsed is listed for the deadline, not for the parse error the
// canceled parser returned.
func walkFile(ctx context.Context, ex *static.Extractor, p *static.Parser, proofs *vendorProofs, rel string, lang static.Language, d fs.DirEntry) (report.SkipReason, bool) {
	if ctx.Err() != nil {
		return report.SkipBudget, true
	}
	reason, gap := addRepoFile(ctx, ex, p, proofs, rel, lang, d)
	if gap && ctx.Err() != nil {
		return report.SkipBudget, true
	}
	return reason, gap
}

// pastDeadline marks a stage's finding as cut by the deadline once ctx is
// done. Only the deadline cancels a scan's context.
func pastDeadline(ctx context.Context, f *report.Finding) bool {
	if ctx.Err() == nil {
		return false
	}
	f.Reason = reasonDeadline
	return true
}
