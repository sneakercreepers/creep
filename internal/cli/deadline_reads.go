package cli

import (
	"context"
	"fmt"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/reader"
)

// deadlineReads is the slicer's Read under the scan deadline. Past it,
// nothing is read from disk: each refused path is remembered, so relabel
// can list the files the slicer never reached, and their hypotheses, as
// budget rather than as failed reads. Only the file whose redaction the
// deadline cut keeps the reader's own reason (redact_failed).
type deadlineReads struct {
	ctx     context.Context
	read    func(path string) ([]byte, error)
	refused map[string]bool
}

func newDeadlineReads(ctx context.Context, read func(string) ([]byte, error)) *deadlineReads {
	return &deadlineReads{ctx: ctx, read: read, refused: map[string]bool{}}
}

// Read reads path, or refuses it once the deadline has passed.
func (d *deadlineReads) Read(path string) ([]byte, error) {
	if d.ctx.Err() != nil {
		d.refused[path] = true
		return nil, fmt.Errorf("read %q: %w", path, context.Cause(d.ctx))
	}
	return d.read(path)
}

// relabel names every file Read refused, and each of its hypotheses, for the
// deadline.
func (d *deadlineReads) relabel(rep *reader.SliceReport, targets []reader.Target) {
	if len(d.refused) == 0 {
		return
	}
	pathOf := make(map[reader.HypothesisID]string, len(targets))
	for _, t := range targets {
		pathOf[t.Hypothesis] = t.Path
	}
	for i, n := range rep.NotScanned {
		if d.refused[n.Path] {
			rep.NotScanned[i].Reason = gateway.SkipBudget
		}
	}
	for i, n := range rep.NotEvaluated {
		if d.refused[pathOf[n.Hypothesis]] {
			rep.NotEvaluated[i].Reason = reader.SkipReason(reasonDeadline)
		}
	}
}
