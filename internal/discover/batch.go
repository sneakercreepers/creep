package discover

import (
	"context"
	"errors"
	"strings"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/redact"
)

// flush sends the pending batch with a canary planted in it and applies
// the reply. Every file of the batch ends with a Coverage.
func (r *run) flush(ctx context.Context) {
	secs := r.pending
	r.pending, r.used = nil, 0
	if len(secs) == 0 {
		return
	}
	batch, c, ok := plantCanary(r.d.Seed, secs)
	if !ok {
		r.failAll(secs, CoverageCanaryMissed, ReasonParseFailed)
		return
	}
	prompt := renderBatch(batch)
	a, err := models.Complete[Answer](ctx, r.d.Model, models.Request{
		Purpose:    purpose,
		System:     r.system,
		Prompt:     prompt,
		Redactions: r.d.Redactor.MarkerCounts(prompt),
		Schema:     Schema(),
		Grammar:    Grammar(),
	})
	if err != nil {
		r.callFailed(secs, err)
		return
	}
	if !inBounds(a, batch) {
		r.failAll(secs, CoverageSendFailed, ReasonParseFailed)
		return
	}
	r.apply(a, batch, c)
}

// callFailed lists a batch with no reply. An invalid reply is the
// model's problem with this batch, so the run goes on; any other error
// (budget, consent, transport, status) holds for later calls too and stops
// the model path.
func (r *run) callFailed(secs []section, err error) {
	var invalid *models.InvalidOutputError
	reason := ReasonSendFailed
	switch {
	case errors.As(err, &invalid):
		r.failAll(secs, CoverageSendFailed, ReasonParseFailed)
		return
	case errors.Is(err, gateway.ErrBudgetExhausted):
		reason = ReasonBudget
	case errors.Is(err, redact.ErrRunFull):
		reason = ReasonRunFull
	}
	r.failAll(secs, CoverageSendFailed, reason)
	r.halt(CoverageSendFailed, reason, err)
}

func (r *run) failAll(secs []section, cov Coverage, reason Reason) {
	for _, s := range secs {
		r.work[s.work].fail(cov, reason)
	}
}

// inBounds checks a reply against the batch it answers: every file index
// names a file of the batch (F1), every span lies inside that file's
// lines, and every sink sits on a line that holds code. Any proposal out
// of bounds makes the whole reply invalid (ADR 0017).
func inBounds(a Answer, batch []section) bool {
	fits := func(file, end int) bool { return file < len(batch) && end <= len(batch[file].lines) }
	for _, e := range a.Entries {
		if !fits(e.File, e.End) {
			return false
		}
	}
	for _, s := range a.Auth {
		if !fits(s.File, s.End) {
			return false
		}
	}
	for _, s := range a.Sinks {
		if !fits(s.File, s.Line) || strings.TrimSpace(batch[s.File].lines[s.Line-1]) == "" {
			return false
		}
	}
	return true
}

// apply records a valid reply. Canary proposals are checked and never
// recorded; a missed canary makes every file of the batch canary_missed,
// but its proposals are still kept, since union only adds. A cap affects
// only its own file.
func (r *run) apply(a Answer, batch []section, c canary) {
	found := c.found(a)
	for i, s := range batch {
		if s.work < 0 {
			continue
		}
		w := &r.work[s.work]
		truncated := w.take(a, i)
		switch {
		case !found:
			w.fail(CoverageCanaryMissed, ReasonParseFailed)
		case truncated:
			w.fail(CoverageTruncated, ReasonTruncated)
		default:
			w.file.Coverage = CoverageReadFull
		}
	}
}

// take records the proposals for batch file index file and reports
// whether the file reached a cap.
func (w *fileWork) take(a Answer, file int) bool {
	entries, sinks, auth := 0, 0, 0
	for _, e := range a.Entries {
		if e.File == file {
			w.entries = append(w.entries, entryProp{lines: span(e.Start, e.End), kind: entryKind(e.Kind)})
			entries++
		}
	}
	for _, s := range a.Sinks {
		if s.File == file {
			w.sinks = append(w.sinks, sinkFrom(a, s))
			sinks++
		}
	}
	for _, s := range a.Auth {
		if s.File == file {
			w.auth = append(w.auth, span(s.Start, s.End))
			auth++
		}
	}
	return entries == MaxEntriesPerFile || sinks == MaxSinksPerFile || auth == MaxAuthPerFile
}

// sinkFrom converts a validated sink proposal, with its entry's lines when
// it names one (Validate checked the entry is in the same file).
func sinkFrom(a Answer, s SinkProposal) sinkProp {
	kind, _ := sinkKindByName(s.Kind)
	p := sinkProp{line: span(s.Line, s.Line).Start, kind: kind}
	if s.Entry != noEntry {
		e := a.Entries[s.Entry]
		p.entry, p.hasEntry = span(e.Start, e.End), true
	}
	return p
}

// span converts validated line numbers, which are within 1..MaxLine.
func span(start, end int) Span {
	return Span{Start: uint32(start), End: uint32(end)} //nolint:gosec // G115: Validate keeps lines within 1..MaxLine
}

func entryKind(name string) EntryKind {
	return EntryKind(indexOf(entryKindNames, name) + 1) //nolint:gosec // G115: Validate checked the name
}
