package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/report"
)

// errScanDeadline is the run context's cause once budget.max_seconds has
// passed (#260).
var errScanDeadline = errors.New("scan deadline reached (budget.max_seconds)")

// reasonDeadline is what the deadline leaves behind, files and findings
// alike. Report v1 is frozen (ADR 0009, ADR 0017), so it reuses budget: the
// deadline is the run's time budget, and budget already ends a run
// incomplete.
const reasonDeadline = string(report.SkipBudget)

// startDeadline cancels ctx with errScanDeadline after left (at once when
// it is not positive). The returned stop disarms it and reports whether it
// fired.
func startDeadline(ctx context.Context, cancel context.CancelCauseFunc, left time.Duration) (stop func() bool) {
	timer := time.AfterFunc(left, func() { cancel(errScanDeadline) })
	return func() bool {
		timer.Stop()
		return errors.Is(context.Cause(ctx), errScanDeadline)
	}
}

// scanWithin runs the repository scan and the optional scanners under the
// scan deadline. Calibration reads no repository text, so the deadline
// starts after it and a hostile repository cannot spend it there. Each stage
// lists what the deadline cut; a run it cut stops with reason budget and is
// never clean.
func (s *session) scanWithin(ctx context.Context, cancel context.CancelCauseFunc, tier calibrate.Tier, files repoFiles, stderr io.Writer) (scanResult, error) {
	// A resumed run gets only what the original left (#335).
	stop := startDeadline(ctx, cancel, s.timeLeft())
	res, err := s.scan(ctx, tier, files)
	if err == nil {
		res.scanners = runScanners(ctx, s.cfg.Scanners.Enabled, s.deps.scannerRunner(), stderr)
	}
	if fired := stop(); err != nil || !fired {
		return res, err
	}
	fmt.Fprintf(stderr, "creep scan: the scan deadline of %d s (budget.max_seconds) passed; the work left is listed as not evaluated (reason %s)\n", s.cfg.Budget.MaxSeconds, reasonDeadline)
	if res.stop == "" {
		res.stop = reasonDeadline
	}
	return res, nil
}

// deadlineDiscovery names for the deadline what discovery left undone once
// ctx is done: a file its Read refused (deadlineReads), and a file whose
// batch the deadline cut or never sent (send_failed, the reason discovery
// gives every file after a failed call). A file listed for its own reason
// before the deadline keeps it, as does the file whose redaction the
// deadline cut (redact_failed).
func deadlineDiscovery(ctx context.Context, files []discover.File, paths []string, refused map[string]bool) {
	if ctx.Err() == nil {
		return
	}
	for i, path := range paths {
		if i >= len(files) {
			return
		}
		f := &files[i]
		if f.Reason == discover.ReasonSendFailed || (f.Reason == discover.ReasonReadFailed && refused[path]) {
			f.Reason = discover.ReasonBudget
		}
	}
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
