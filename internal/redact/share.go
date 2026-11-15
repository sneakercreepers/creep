package redact

import (
	"errors"
	"strings"
)

// One Redact or File call may add at most this share of the run's caps, so a
// single crafted file (hundreds of placeholder values of one repeated byte,
// issue #105) cannot fill the run and end the scan for every file after it.
// The shares leave room for real files: a file at MaxFileBytes of distinct
// email addresses holds about 30k values, and one with an unterminated private
// key stores about its own size (TestFileKeyCountsOnce). Placeholders of one
// repeated byte are rarer: past the 16 that one window holds, a call may add
// 32 more, so it takes 8 such files, each accepted, to fill the overflow list.
const (
	maxCallValues   = maxRunValues / 4      // 32768
	maxCallBytes    = maxRunBytes / 4       // 8 MiB
	maxCallOverflow = maxOverflowValues / 8 // 32
)

// ErrTooManyValues is returned by Redact or File when the input holds more
// new values than one call may add to the run (32768 values, 8 MiB, or 32
// values that only the overflow list can index). The call returns no
// output and adds nothing to the run, which goes on: callers must list the
// file as not scanned, never send it unredacted.
var ErrTooManyValues = errors.New("redact: input holds more values than one call may add")

// callShare is what the current call has added to the run, so it can be
// held to its share and undone when it goes over.
type callShare struct {
	added    []string // values stored by this call, in order
	bytes    int
	overflow int  // of the added values, those in the overflow list
	over     bool // a value did not fit the share: the call fails
}

// admits reports whether value fits what is left of the call's share.
func (c *callShare) admits(value string) bool {
	if c.over || len(c.added) >= maxCallValues || c.bytes+len(value) > maxCallBytes {
		c.over = true
		return false
	}
	return true
}

// indexValue indexes value for the sweep. When only the overflow list has
// room, the value takes one of the call's overflow slots; when the list is
// full the run ends, and when the call's slots are gone the call fails.
func (s *runState) indexValue(value string) bool {
	overflowed, ok := s.index.add(value, s.call.overflow < maxCallOverflow)
	switch {
	case ok && overflowed:
		s.call.overflow++
	case !ok && s.index.overflowCount >= maxOverflowValues:
		s.full = true
	case !ok:
		s.call.over = true
	}
	return ok
}

// rollback forgets every value the current call stored, newest first, so a
// failed call leaves the run as it found it: same values, same numbering.
func (s *runState) rollback() {
	for i := len(s.call.added) - 1; i >= 0; i-- {
		value := s.call.added[i]
		m := s.byValue[value]
		delete(s.byValue, value)
		delete(s.byMarker, m)
		label := m[1:strings.LastIndexByte(m, '_')]
		if s.counters[label]--; s.counters[label] == 0 {
			delete(s.counters, label)
		}
		s.bytes -= len(value)
		if len(value) >= minSweepLen {
			s.index.removeLast(value)
		}
	}
	s.call = callShare{}
}
