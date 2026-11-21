package redact

import (
	"cmp"
	"fmt"
)

// A find keeps at most one occurrence per sweepSpanBytes of text, plus
// sweepSpanSlack, so its memory is linear with a small constant whatever the
// run knows. Kept occurrences of one value do not overlap and nested ones of
// one label are dropped (find), so ordinary text keeps far fewer: a text
// made only of known values of minSweepLen bytes keeps one per 8 bytes. Text
// crafted to keep more (many values of different labels, or under crowded
// windows, overlapping without nesting) fails closed.
const (
	sweepSpanBytes = 4
	sweepSpanSlack = 1024
)

// sweepStopEvery is how many positions find checks between two looks at the
// run's context.
const sweepStopEvery = 4096

// sweep finds the values of earlier calls in text and in its copy without
// format characters (withoutFormat). It returns the context's cause once the
// run's context is done, so a stopped sweep never yields partial text.
func (r *Redactor) sweep(text string) ([]span, error) {
	var tooMany error
	found := withoutFormat(text, func(t string) []span {
		spans, err := r.state.index.find(t, r.done())
		tooMany = cmp.Or(tooMany, err)
		return spans
	})
	if err := r.stopped(); err != nil {
		return nil, err
	}
	return found, tooMany
}

// sweepScan is the state of one find: the text's prefix hashes, the
// occurrences kept so far and, per label, the kept occurrence that ends
// furthest.
type sweepScan struct {
	x       *sweepIndex
	text    string
	prefix  []uint64
	scan    uint64
	keepAll bool  // keep every occurrence: the reference the tests compare with
	reach   []int // label id -> index in found of its furthest kept occurrence, or -1
	found   []span
	limit   int
}

// find returns the occurrences of known values in text that rendering needs.
// Like a search per value, occurrences of one value do not overlap;
// occurrences of different values may. Each position checks at most
// maxWindowValues values from its window plus the overflow values that start
// with the byte at that position, and skips a value whose last occurrence
// reaches past it before computing any hash.
//
// An occurrence inside a kept occurrence of a value with the same label is
// dropped, and a kept one is replaced by one that contains it, so a run of
// one byte keeps one span, not one per known run of it per position (#106).
// Rendering reads a swept part only by its bounds and label (merge.go), and a
// part inside another of the same label changes neither the bytes masked,
// nor the longest part of a label, nor which parts reach past it, nor the
// label a piece takes: the output and the values stored are the same as with
// every occurrence. Text that would still keep more than sweepLimit fails
// closed with ErrTooManyValues. Once done is closed it stops and returns
// nothing; the caller then drops the call.
func (x *sweepIndex) find(text string, done <-chan struct{}) ([]span, error) {
	return x.scanText(text, done, false)
}

func (x *sweepIndex) scanText(text string, done <-chan struct{}, keepAll bool) ([]span, error) {
	if len(x.values) == 0 || len(text) < minSweepLen {
		return nil, nil
	}
	s := x.newScan(text, keepAll)
	for p := 0; p+minSweepLen <= len(text); p++ {
		if p%sweepStopEvery == 0 && closed(done) {
			return nil, nil
		}
		if !s.check(p, x.windows[window(text, p)]) || !s.check(p, x.overflow[text[p]]) {
			return nil, fmt.Errorf("redact: sweep of %d bytes keeps over %d occurrences: %w", len(text), s.limit, ErrTooManyValues)
		}
	}
	return s.found, nil
}

// newScan starts find number x.scans+1: every value's last occurrence from an
// earlier find is ignored without clearing them all.
func (x *sweepIndex) newScan(text string, keepAll bool) sweepScan {
	x.scans++
	reach := make([]int, len(x.labels))
	for i := range reach {
		reach[i] = -1
	}
	return sweepScan{
		x: x, text: text, prefix: x.prefixHashes(text), scan: x.scans,
		keepAll: keepAll, reach: reach, limit: sweepLimit(len(text)),
	}
}

// sweepLimit is how many occurrences a find over n bytes may keep.
func sweepLimit(n int) int { return n/sweepSpanBytes + sweepSpanSlack }

// check records each value among ids that occurs with its window at p. It
// returns false once the find keeps more than its limit.
func (s *sweepScan) check(p int, ids []int) bool {
	values, prefix, scan := s.x.values, s.prefix, s.scan
	for _, id := range ids {
		v := &values[id]
		start := p - v.offset
		end := start + v.length
		if (v.scan == scan && start < v.lastEnd) || start < 0 || end >= len(prefix) {
			continue
		}
		if substringHash(prefix, start, end, v.scale) != v.hash {
			continue
		}
		v.scan, v.lastEnd = scan, end
		if !s.keep(span{start: start, end: end, known: s.x.labels[v.label]}, v.label) {
			return false
		}
	}
	return true
}

// keep adds sp, an occurrence of a value with label id label, unless it lies
// inside the label's furthest kept occurrence; one that contains that
// occurrence takes its place. It returns false once the limit is passed.
func (s *sweepScan) keep(sp span, label int) bool {
	if i := s.reach[label]; i >= 0 && !s.keepAll {
		k := s.found[i]
		switch {
		case k.start <= sp.start && sp.end <= k.end:
			return true
		case sp.start <= k.start && k.end <= sp.end:
			s.found[i] = sp
			return true
		case sp.end <= k.end:
			return s.add(sp)
		}
	}
	s.reach[label] = len(s.found)
	return s.add(sp)
}

func (s *sweepScan) add(sp span) bool {
	if len(s.found) >= s.limit && !s.keepAll {
		return false
	}
	s.found = append(s.found, sp)
	return true
}
