package discover

import (
	"context"
	"errors"
	"strings"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/redact"
)

// flush sends the pending batch with a canary planted in it to every
// sample's model and applies each reply. Every file of the batch ends with
// a Coverage; a failure in any sample stays (ADR 0024).
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
	r.number(secs)
	prompt := renderBatch(batch)
	for i, m := range r.models() {
		if r.stop != ReasonNone {
			return // an earlier sample stopped the model path
		}
		r.ask(ctx, m, uint8(i), secs, batch, c, prompt) //nolint:gosec // G115: i < MaxSamples
	}
}

// ask sends one sample of a batch and applies its reply.
func (r *run) ask(ctx context.Context, m *models.HTTP, sample uint8, secs []section, batch []section, c canary, prompt string) {
	replyCap, _ := ReplyTokens(r.d.Tier, len(batch)) // newRun checked the tier
	a, err := models.Complete[Answer](ctx, m, models.Request{
		Purpose:         purpose,
		System:          r.system,
		Prompt:          prompt,
		Redactions:      r.d.Redactor.MarkerCounts(prompt),
		Schema:          Schema(),
		Grammar:         Grammar(),
		MaxOutputTokens: replyCap,
	})
	if err != nil {
		r.callFailed(secs, err)
		return
	}
	rep, err := a.reply() // Validate passed, so this cannot fail; checked anyway
	if err != nil || !inBounds(rep, batch) {
		r.failAll(secs, CoverageSendFailed, ReasonParseFailed)
		return
	}
	r.apply(rep, batch, c, sample)
}

// callFailed lists a batch with no reply. An invalid reply is the
// model's problem with this batch, so the run goes on; one cut off at the
// reply cap on every attempt (retries counted) is truncated, not
// parse_failed, so the report says why. Any other error (budget, consent,
// transport, status) holds for later calls too and stops the model path.
func (r *run) callFailed(secs []section, err error) {
	var invalid *models.InvalidOutputError
	reason := ReasonSendFailed
	switch {
	case errors.As(err, &invalid) && invalid.Truncated:
		r.failAll(secs, CoverageTruncated, ReasonTruncated)
		return
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

// number gives the batch about to be sent the next batch number.
func (r *run) number(secs []section) {
	r.batches++
	for _, s := range secs {
		r.work[s.work].file.Batch = r.batches
	}
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
func inBounds(a reply, batch []section) bool {
	fits := func(file, end int) bool { return file < len(batch) && end <= len(batch[file].lines) }
	for _, e := range a.entries {
		if !fits(e.file, e.end) {
			return false
		}
	}
	for _, s := range a.auth {
		if !fits(s.file, s.end) {
			return false
		}
	}
	for _, s := range a.sinks {
		if !fits(s.file, s.line) || strings.TrimSpace(batch[s.file].lines[s.line-1]) == "" {
			return false
		}
	}
	return true
}

// apply records a valid reply of one sample. Canary proposals are
// checked and never recorded; a missed canary makes every file of the
// batch canary_missed, but its proposals are still kept, since union only
// adds. A cap affects only its own file. A file an earlier sample of the
// batch failed stays failed.
func (r *run) apply(a reply, batch []section, c canary, sample uint8) {
	found := c.found(a)
	for i, s := range batch {
		if s.work < 0 {
			continue
		}
		w := &r.work[s.work]
		truncated := w.take(a, i, sample, itemsPerFile[r.d.Tier])
		switch {
		case w.failed():
			// An earlier sample's failure stays: union only adds.
		case !found:
			w.fail(CoverageCanaryMissed, ReasonParseFailed)
		case truncated:
			w.fail(CoverageTruncated, ReasonTruncated)
		default:
			w.file.Coverage = CoverageReadFull
		}
	}
}

// take records the proposals of one sample for batch file index file and
// reports whether the file reached a cap: a schema cap, or the asked
// items, the most the prompt let the model report for one file.
func (w *fileWork) take(a reply, file int, sample uint8, asked int) bool {
	entries, sinks, auth := 0, 0, 0
	for _, e := range a.entries {
		if e.file == file {
			w.entries = append(w.entries, entryProp{lines: span(e.start, e.end), kind: entryKind(e.kind)})
			entries++
		}
	}
	for _, s := range a.sinks {
		if s.file == file {
			p := sinkFrom(a, s)
			p.samples = 1 << sample
			w.sinks = append(w.sinks, p)
			sinks++
		}
	}
	for _, s := range a.auth {
		if s.file == file {
			w.auth = append(w.auth, span(s.start, s.end))
			auth++
		}
	}
	return entries == MaxEntriesPerFile || sinks == MaxSinksPerFile || auth == MaxAuthPerFile || entries+sinks+auth >= asked
}

// sinkFrom converts a validated sink proposal, with its entry's lines when
// it names one (Validate checked the entry is in the same file).
func sinkFrom(a reply, s sinkRec) sinkProp {
	kind, _ := sinkKindByName(s.kind)
	p := sinkProp{line: span(s.line, s.line).Start, kind: kind}
	if s.entry != noEntry {
		e := a.entries[s.entry]
		p.entry, p.hasEntry = span(e.start, e.end), true
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
