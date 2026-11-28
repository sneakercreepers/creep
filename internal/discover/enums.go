package discover

// FileID is the index of a path in the list given to Run. RouteID and
// SinkID are assigned by creep, never taken from a model.
type (
	FileID  uint32
	RouteID uint32
	SinkID  uint32
)

// Span is an inclusive range of 1-based line numbers.
type Span struct {
	Start uint32
	End   uint32
}

// SinkKind has the same values as planner.SinkKind, so
// the caller maps it by explicit switch. The zero value is not a kind.
type SinkKind uint8

// Sink kinds.
const (
	SinkSQL SinkKind = iota + 1
	SinkShell
	SinkFile
	SinkHTTPClient
	SinkTemplate
	SinkNoSQL
	SinkCodeEval
	SinkDeserialize
)

// sinkKinds lists every kind with its wire name, in the order the prompts,
// the schema and the tripwire table use.
var sinkKinds = []struct {
	kind SinkKind
	name string
}{
	{SinkSQL, "sql"}, {SinkNoSQL, "nosql"}, {SinkShell, "shell"},
	{SinkCodeEval, "code_eval"}, {SinkDeserialize, "deserialize"},
	{SinkFile, "file"}, {SinkHTTPClient, "http_client"}, {SinkTemplate, "template"},
}

func sinkKindByName(name string) (SinkKind, bool) {
	for _, k := range sinkKinds {
		if k.name == name {
			return k.kind, true
		}
	}
	return 0, false
}

// String returns the kind's wire name, or "unknown".
func (k SinkKind) String() string {
	for _, s := range sinkKinds {
		if s.kind == k {
			return s.name
		}
	}
	return "unknown"
}

// Methods has the same bits as planner.Methods.
type Methods uint16

// HTTP methods. MethodOther stands for any other or unknown method.
const (
	MethodGet Methods = 1 << iota
	MethodPost
	MethodPut
	MethodPatch
	MethodDelete
	MethodHead
	MethodOptions
	MethodTrace
	MethodOther
)

// AllMethods is every method bit. Every route gets it: the planner ranks
// write methods higher, so a method list from a model could lower a
// route's rank, and the schema has none (ADR 0017).
const AllMethods = MethodOther<<1 - 1

// EntryKind is what kind of entry point a model proposed. It never changes
// planning. The zero value is the synthetic per-file entry point.
type EntryKind uint8

// Entry kinds, in the order of entryKindNames.
const (
	EntryHTTP EntryKind = iota + 1
	EntryRPC
	EntryMessage
	EntryCLI
	EntryScheduled
	EntryOther
)

var entryKindNames = []string{"http", "rpc", "message", "cli", "scheduled", "other"}

// Coverage says how much of a file discovery read. Only CoverageReadFull
// and CoverageNotSource let a run be complete (ADR 0017 D2).
type Coverage uint8

// Coverage values. The zero value is not a coverage.
const (
	// CoverageNotSource is a file discovery does not read by design: a
	// known non-code format (ReasonNotCode) or binary bytes (ReasonBinary).
	CoverageNotSource Coverage = iota + 1
	// CoverageReadFull means the model read the whole redacted file, its
	// batch's canary was found and no cap was hit.
	CoverageReadFull
	// CoverageTruncated means the reply hit a per-file cap, or was cut off
	// at the reply cap on every attempt.
	CoverageTruncated
	// CoverageSendFailed means the file got no valid reply: the call
	// failed, the reply was invalid, or the run stopped (see Reason).
	CoverageSendFailed
	// CoverageCanaryMissed means the reply missed its batch's canary, so
	// it cannot be trusted to be complete.
	CoverageCanaryMissed
	// CoverageNotRead means creep refused to send the file (see Reason).
	CoverageNotRead
)

// Reason says why a file was not read in full. Each value is a report v1
// not-evaluated reason with the same name (ADR 0017 D3; not_code and
// binary since #366). It is a closed set: no error text that could carry
// repository bytes reaches run output.
type Reason uint8

// Reasons. ReasonNone is the zero value.
const (
	ReasonNone         Reason = iota
	ReasonReadFailed          // read_failed: Read returned an error
	ReasonTooLarge            // too_large: over redact.MaxFileBytes or one discovery call
	ReasonLineTooLong         // line_too_long: redact.ErrLineTooLong
	ReasonRedactFailed        // redact_failed: any other redact.File error
	ReasonLinesShifted        // lines_shifted: redaction joined lines
	ReasonRunFull             // run_full: redact.ErrRunFull stopped the run
	ReasonBudget              // budget: the token or call budget stopped the run
	ReasonSendFailed          // send_failed: a call error stopped the run
	ReasonParseFailed         // parse_failed: invalid reply or missed canary
	ReasonTruncated           // truncated: a per-file or reply cap was reached
	ReasonNotCode             // not_code: a text format of formats.txt, never opened (by design)
	ReasonBinary              // binary: a NUL or, under a binary format's name, non-UTF-8 bytes (by design)
)

var reasonNames = []string{
	"read_failed", "too_large", "line_too_long", "redact_failed", "lines_shifted",
	"run_full", "budget", "send_failed", "parse_failed", "truncated",
	"not_code", "binary",
}

// String returns the report v1 reason name, or "" for ReasonNone.
func (r Reason) String() string {
	if r == ReasonNone || int(r) > len(reasonNames) {
		return ""
	}
	return reasonNames[r-1]
}

// Origin records which step proposed a sink. A sink both found is one sink
// with both bits; union never drops a candidate.
type Origin uint8

// Origins.
const (
	OriginTripwire Origin = 1 << iota
	OriginModel
)
