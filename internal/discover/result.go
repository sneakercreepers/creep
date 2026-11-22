package discover

import "math/bits"

// Result is everything discovery found. It holds only IDs, enums, line
// numbers and booleans, never repository text (text_test.go): paths stay
// with the caller, indexed by FileID. internal/cli copies Routes and Sinks
// into planner.Input field by field, and builds each reader.Target from a
// sink, its route's first line as SourceLine and its own line as SinkLine,
// with the path at Files[sink.File].
type Result struct {
	Files  []File // one per path given to Run, Files[i].ID == i
	Routes []Route
	Sinks  []Sink
	Auth   []AuthSpan
	// Incomplete means the model path stopped before the last file
	// (run_full, budget or send_failed): never a clean result.
	Incomplete bool
	// Samples is how many times each batch was sent: 1, or the N of
	// --stability N (ADR 0024).
	Samples uint8
}

// File is what discovery knows about one path.
type File struct {
	ID        FileID
	Language  Language // zero when the file is not source
	Manifest  Manifest
	Container Container
	Coverage  Coverage
	Reason    Reason // why Coverage is not read_full; ReasonNone otherwise
	// Batch is the 1-based number of the discovery call that sent the
	// file whole, in send order; 0 when it was never sent. It lets the
	// caller count whole-file egress and name a failed batch's cause.
	Batch uint32
	// TripwireCut means the file reached MaxTripwireHits; it reports as
	// truncated.
	TripwireCut bool
}

// Route is one entry point. Every route is planned at the worst case:
// all methods, not authenticated (ADR 0017). FileLevel marks the one
// synthetic entry point per file that holds the sinks no proposed entry
// point covers.
type Route struct {
	ID            RouteID
	File          FileID
	Lines         Span
	Kind          EntryKind // zero for FileLevel; never changes planning
	Methods       Methods   // always AllMethods
	Authenticated bool      // always false
	FileLevel     bool
}

// Sink is one candidate: a tripwire hit, a model proposal or both. Its
// flags are always the planner's highest-risk values.
type Sink struct {
	ID     SinkID
	Route  RouteID
	File   FileID
	Line   uint32
	Kind   SinkKind
	Origin Origin
	// SeenBy has bit i set when sample i named the candidate: every
	// sample's bit for a tripwire hit, which needs no model. It only labels
	// a finding; planning never reads it, so it cannot drop or lower a
	// candidate (ADR 0024).
	SeenBy        uint8
	DynamicArg    bool // always true
	Parameterized bool // always false
	Indirect      bool // always false
}

// Seen is how many of the Result's samples named the sink.
func (s Sink) Seen() int { return bits.OnesCount8(s.SeenBy) }

// AuthSpan is a span a model said holds an auth check. It may only widen
// the reader's slice; it never sets Authenticated or skips a sink.
type AuthSpan struct {
	File  FileID
	Lines Span
}

// Complete reports whether the run may count as read in full (ADR 0017
// D2, first two rules): the model path did not stop, every source file was
// read in full with its batch's canary found, and no cap was hit. Whether
// every tripwire candidate was evaluated is the caller's to check.
func (r Result) Complete() bool {
	if r.Incomplete {
		return false
	}
	for _, f := range r.Files {
		if f.TripwireCut || f.Coverage != CoverageReadFull && f.Coverage != CoverageNotSource {
			return false
		}
	}
	return true
}
