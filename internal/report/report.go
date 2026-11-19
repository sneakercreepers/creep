package report

import (
	"errors"
	"regexp"
	"slices"

	"github.com/sneakercreepers/creep/internal/buildinfo"
	"github.com/sneakercreepers/creep/internal/state"
)

// SchemaVersion is the JSON report contract version. Removing or retyping a
// field needs a bump and a new docs/schemas/report-vN.json.
const SchemaVersion = 1

// Status is what the run concluded about a finding.
type Status string

// Finding statuses, strongest first.
const (
	StatusVerified     Status = "verified"
	StatusProbable     Status = "probable"
	StatusDiscarded    Status = "discarded"
	StatusNotEvaluated Status = "not_evaluated"
)

// statusRank orders findings in every format and doubles as the closed set.
var statusRank = map[Status]int{
	StatusVerified: 0, StatusProbable: 1, StatusDiscarded: 2, StatusNotEvaluated: 3,
}

// ClassStatus is how much of one vulnerability class the run evaluated.
type ClassStatus string

// Class statuses.
const (
	ClassCovered      ClassStatus = "covered"
	ClassPartial      ClassStatus = "partial"
	ClassNotEvaluated ClassStatus = "not_evaluated"
)

// SkipReason is why a file was not evaluated in full, a closed set. The
// first seven mirror gateway.SkipReason; report may not import gateway
// (layer table), so the CLI converts and a test there keeps the sets equal.
type SkipReason string

// Reasons a file was not evaluated in full.
const (
	SkipReadFailed   SkipReason = "read_failed"
	SkipTooLarge     SkipReason = "too_large"
	SkipLineTooLong  SkipReason = "line_too_long"
	SkipRedactFailed SkipReason = "redact_failed"
	SkipRunFull      SkipReason = "run_full"
	SkipSendFailed   SkipReason = "send_failed"
	SkipBudget       SkipReason = "budget"
	// SkipLinesShifted is reader.FileLinesShifted: redaction joined lines
	// (a multi-line key), so no slice of the file could be numbered.
	SkipLinesShifted SkipReason = "lines_shifted"
	// The walk and discovery (ADR 0009, ADR 0017 D2). Vendor, generated and
	// minified files are left out by design; the rest are gaps in the run.
	SkipVendor      SkipReason = "vendor"
	SkipGenerated   SkipReason = "generated"
	SkipMinified    SkipReason = "minified"
	SkipNotRegular  SkipReason = "not_regular"  // a link or special file named as source
	SkipInvalidPath SkipReason = "invalid_path" // the walk refused the repo-relative name
	SkipParseFailed SkipReason = "parse_failed" // discovery's reply was invalid or missed the batch's canary
	SkipTruncated   SkipReason = "truncated"    // partial: a tripwire or reply cap cut the file
	// Kept for JSON v1 readers: no run since ADR 0017 emits these two.
	SkipSyntaxError SkipReason = "syntax_error"
	SkipUnsupported SkipReason = "unsupported_language"
)

var skipReasons = map[SkipReason]bool{
	SkipReadFailed: true, SkipTooLarge: true, SkipLineTooLong: true, SkipRedactFailed: true,
	SkipRunFull: true, SkipSendFailed: true, SkipBudget: true, SkipLinesShifted: true,
	SkipVendor: true, SkipGenerated: true, SkipMinified: true, SkipNotRegular: true,
	SkipInvalidPath: true, SkipParseFailed: true, SkipSyntaxError: true, SkipTruncated: true,
	SkipUnsupported: true,
}

// Incomplete reasons when the run state gives none.
const (
	ReasonScanStopped = "scan_stopped"  // the gateway scan stopped early
	ReasonRunNotEnded = "run_not_ended" // the run state has no end line
)

// idPattern matches finding IDs, class names and reasons: identifiers, never
// free text, so `creep why <id>` and every format can print them safely.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ValidID reports whether s is a well-formed finding ID, so `creep why`
// refuses anything else before reading a report.
func ValidID(s string) bool { return idPattern.MatchString(s) }

// maxConfidence is the top of the reader's confidence scale.
const maxConfidence = 100

// ErrInvalid is wrapped by every validation error from New.
var ErrInvalid = errors.New("invalid report input")

// Tool identifies the creep build that wrote the report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// RunInfo says whether the report can be read as a clean result.
type RunInfo struct {
	Incomplete bool   `json:"incomplete"`
	Reason     string `json:"reason,omitempty"` // an ID; empty when complete
}

// Finding is one hypothesis and its verdict. Path comes from the scanned
// repository and must pass ValidPath (relative, slash-separated, clean);
// Line is 1-based, 0 for the file.
// The optional fields are the evidence `creep why` prints (ADR 0009).
type Finding struct {
	ID     string `json:"id"`
	Class  string `json:"class"`
	Status Status `json:"status"`
	Path   string `json:"path"`
	Line   int    `json:"line"`
	// Reason is an ID saying why a not-evaluated finding was not decided
	// (step_cap, budget, inconclusive, ...).
	Reason string `json:"reason,omitempty"`
	// Partial means the verdict came from a slice that left lines out.
	Partial    bool        `json:"partial,omitempty"`
	Confidence int         `json:"confidence,omitempty"` // the reader's 0-100
	Evidence   []LineRange `json:"evidence,omitempty"`   // lines the reader cited
}

// LineRange is an inclusive range of 1-based lines in the finding's file.
type LineRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// ClassCoverage is one class's status and its calibration result: Detected
// of Tasks seeded tasks found, with a 95% Wilson interval for the recall.
type ClassCoverage struct {
	Class    string      `json:"class"`
	Status   ClassStatus `json:"status"`
	Detected int         `json:"detected"`
	Tasks    int         `json:"tasks"`
	CILow    float64     `json:"ci_low"`
	CIHigh   float64     `json:"ci_high"`
}

// NotEvaluated is a file the model never saw in full. Path comes from the
// scanned repository.
type NotEvaluated struct {
	Path   string     `json:"path"`
	Reason SkipReason `json:"reason"`
}

// Coverage is what was and was not evaluated. Scanners lists the optional
// external scanners and the classes they would cover (ADR 0010).
type Coverage struct {
	Classes      []ClassCoverage   `json:"classes"`
	NotEvaluated []NotEvaluated    `json:"not_evaluated"`
	Scanners     []ScannerCoverage `json:"scanners,omitempty"`
}

// Report is the JSON contract (schema_version 1) and the input of every
// format. Build it with New.
type Report struct {
	SchemaVersion int          `json:"schema_version"`
	Tool          Tool         `json:"tool"`
	Run           RunInfo      `json:"run"`
	Findings      []Finding    `json:"findings"`
	Coverage      Coverage     `json:"coverage"`
	DataHandling  DataHandling `json:"data_handling"`
	// Discovery is the inventory, the whole-file egress and the failed
	// discovery batches, for Markdown and the text summary (ADR 0017 D3).
	// It is not part of the contract, so a report read back has none.
	Discovery Discovery `json:"-"`
}

// Input is what a run hands to New. Classes are in the caller's fixed order;
// NotEvaluated in scan order. Only Detected and Tasks of each class are
// read; the interval is computed here.
type Input struct {
	Run            state.Summary
	ScanIncomplete bool // gateway.ScanReport.Incomplete
	Findings       []Finding
	Classes        []ClassCoverage
	NotEvaluated   []NotEvaluated
	Scanners       []ScannerCoverage // in the caller's fixed order
	DataHandling   DataHandling
	Discovery      Discovery
}

// New validates in and builds the report. Unknown statuses, reasons or
// malformed IDs are errors: a report never guesses.
func New(in Input) (*Report, error) {
	run := runInfo(in.Run, in.ScanIncomplete)
	findings, err := checkFindings(in.Findings)
	if err != nil {
		return nil, err
	}
	classes, err := checkClasses(in.Classes, run.Incomplete)
	if err != nil {
		return nil, err
	}
	skipped, err := checkNotEvaluated(in.NotEvaluated)
	if err != nil {
		return nil, err
	}
	scanners, err := checkScanners(in.Scanners)
	if err != nil {
		return nil, err
	}
	if err := checkDiscovery(in.Discovery); err != nil {
		return nil, err
	}
	info := buildinfo.Get()
	return &Report{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "creep", Version: info.Version, Commit: info.Commit},
		Run:           run,
		Findings:      findings,
		Coverage:      Coverage{Classes: classes, NotEvaluated: skipped, Scanners: scanners},
		DataHandling:  in.DataHandling.normalized(),
		Discovery: Discovery{
			WholeFiles: in.Discovery.WholeFiles,
			Inventory:  slices.Clone(in.Discovery.Inventory), Batches: slices.Clone(in.Discovery.Batches),
		},
	}, nil
}

// runInfo is incomplete unless the run state ended complete and the scan
// did not stop. The state's reason is an ID (state checks its alphabet).
func runInfo(sum state.Summary, scanIncomplete bool) RunInfo {
	if sum.Complete() && !scanIncomplete {
		return RunInfo{}
	}
	reason := sum.Reason
	switch {
	case reason != "" && idPattern.MatchString(reason):
	case scanIncomplete:
		reason = ReasonScanStopped
	default:
		reason = ReasonRunNotEnded
	}
	return RunInfo{Incomplete: true, Reason: reason}
}
