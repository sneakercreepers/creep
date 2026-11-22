package reader

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/repofile"
)

// Class is the vulnerability class a hypothesis names. The caller maps the
// discovered sink kind to it, since reader may not import discover.
type Class uint8

// Classes. The zero value is not a class.
const (
	ClassSQLInjection Class = iota + 1
	ClassCommandInjection
	ClassPathTraversal
	ClassSSRF
	ClassTemplateInjection
	ClassNoSQLInjection
)

var classNames = map[Class]string{
	ClassSQLInjection:      "sql_injection",
	ClassCommandInjection:  "command_injection",
	ClassPathTraversal:     "path_traversal",
	ClassSSRF:              "ssrf",
	ClassTemplateInjection: "template_injection",
	ClassNoSQLInjection:    "nosql_injection",
}

// String returns the class name the user turn shows.
func (c Class) String() string {
	if name, ok := classNames[c]; ok {
		return name
	}
	return "unknown"
}

// Target is one route→sink hypothesis: where its handler and sink are, as
// 1-based lines of the file at Path (discover.Result has both).
type Target struct {
	Hypothesis HypothesisID
	Class      Class
	Path       string // as given to Slicer.Read
	SourceLine int    // the handler's def line
	SinkLine   int
	// Hint is a recipe's hint for this hypothesis, or "". It is untrusted
	// text: Build redacts and escapes it like code, shows it only as "~ "
	// lines of the HINT block, and refuses one over MaxHintBytes or
	// MaxHintLines. It never reaches the planner (ADR 0025).
	Hint string
}

// Hint limits, the same ones a recipe is held to (internal/recipe).
const (
	MaxHintBytes = 400
	MaxHintLines = 8
)

// Slice is the user turn for one hypothesis. Text is built only from
// redact.File output and holds the HYPOTHESIS line and numbered CODE lines;
// Shown are the lines it holds, for Project.
type Slice struct {
	Hypothesis HypothesisID
	Text       string
	Shown      []LineRange
	// Partial means lines were left out or cut to fit the tier's budget, or
	// the walk stopped early; the verdict was reached on less than the slice.
	Partial    bool
	Redactions map[string]int // marker label -> count in Text, for Call.Redactions
	// Tier is the budget Text was cut to; Evaluate refuses any other tier's
	// prompt, so a slice is never sent with a prompt it was not sized for.
	Tier Tier
	// Hinted means Text holds a HINT block, so Evaluate adds the hint note
	// to the system prompt.
	Hinted bool
	// Sink is the sink's line of redact.File output, escaped like Text, for
	// the finding's baseline fingerprint (#27): it is hashed, never sent or
	// printed, and never holds a secret redaction masked.
	Sink string
}

// SkipReason says why a hypothesis was not evaluated. It is a closed set,
// so run output never quotes error text that could carry repository bytes.
type SkipReason string

// The reasons a hypothesis is listed as not evaluated.
const (
	SkipFileNotScanned SkipReason = "file_not_scanned"  // its file is in NotScanned
	SkipRunFull        SkipReason = "run_full"          // redact.ErrRunFull stopped the run
	SkipLineRange      SkipReason = "line_out_of_range" // a line is past the file's end or MaxLine
	SkipLinesShifted   SkipReason = "lines_shifted"     // redaction joined lines, so numbers would not match
	SkipHintRefused    SkipReason = "hint_refused"      // the hint is over its limits or redact.File refused it
)

// FileLinesShifted is the NotScanned reason for a file whose redaction
// joined lines (a multi-line private key): it was redacted but never
// sliced. It extends gateway's closed set of file reasons with one only
// slicing can hit.
const FileLinesShifted = gateway.SkipReason(SkipLinesShifted)

// NotEvaluated is a hypothesis no slice was built for.
type NotEvaluated struct {
	Hypothesis HypothesisID
	Reason     SkipReason
}

// SliceReport is the outcome of Slicer.Build.
type SliceReport struct {
	Slices       []Slice
	NotScanned   []gateway.NotScanned // files never sliced, in first-use order (gateway reasons or FileLinesShifted)
	NotEvaluated []NotEvaluated
	// Incomplete means redact.ErrRunFull stopped the run: it must never be
	// reported as a clean result.
	Incomplete bool
}

// Slicer builds the user turn for each hypothesis. Each file is redacted
// whole with redact.File before any line is picked, so no slice boundary
// can split a secret, and only File output is ever cut.
type Slicer struct {
	Redactor *redact.Redactor // one per run, shared with the model calls
	Tier     Tier
	// Read returns a file's content; the caller opens it without blocking.
	Read func(path string) ([]byte, error)
}

// ErrSlicer means Build got a Slicer or Target it cannot use.
var ErrSlicer = errors.New("reader: invalid slicer input")

// Build builds one slice per target, grouped by file in first-use order.
// A file that cannot be read or that redact.File rejects is never sliced:
// it is listed as not scanned, its hypotheses as not evaluated, and the run
// goes on. ErrRunFull stops the run: that file and every later one are
// listed, the report is Incomplete and the error is returned. Slices built
// before it were redacted in full and stay valid.
func (s Slicer) Build(targets []Target) (SliceReport, error) {
	budget, ok := sliceBudget[s.Tier]
	if !ok {
		return SliceReport{}, fmt.Errorf("%w %q", ErrTier, string(s.Tier))
	}
	if s.Redactor == nil || s.Read == nil {
		return SliceReport{}, fmt.Errorf("%w: Redactor and Read are required", ErrSlicer)
	}
	if err := checkTargets(targets); err != nil {
		return SliceReport{}, err
	}
	var rep SliceReport
	files := groupByPath(targets)
	for i, f := range files {
		if err := s.buildFile(f, budget, &rep); err != nil {
			rep.stop(files[i:])
			return rep, fmt.Errorf("reader slices stopped: %w", err)
		}
	}
	return rep, nil
}

func checkTargets(targets []Target) error {
	for i, t := range targets {
		if _, ok := classNames[t.Class]; !ok {
			return fmt.Errorf("%w: target %d has class %d", ErrSlicer, i, t.Class)
		}
	}
	return nil
}

// fileTargets is the targets that share one file.
type fileTargets struct {
	path    string
	targets []Target
}

func groupByPath(targets []Target) []fileTargets {
	index := map[string]int{}
	var out []fileTargets
	for _, t := range targets {
		i, ok := index[t.Path]
		if !ok {
			i = len(out)
			index[t.Path] = i
			out = append(out, fileTargets{path: t.Path})
		}
		out[i].targets = append(out[i].targets, t)
	}
	return out
}

// buildFile slices one file. It returns an error only when the run must
// stop. The raw content is used only to count its lines, never sliced.
func (s Slicer) buildFile(f fileTargets, budget int, rep *SliceReport) error {
	content, err := s.Read(f.path)
	if err != nil {
		rep.skipFile(f, gateway.SkipReadFailed, SkipFileNotScanned)
		return nil
	}
	text, err := s.Redactor.File(content)
	if err != nil {
		reason, stop := redactSkip(err)
		if stop {
			return err
		}
		rep.skipFile(f, reason, SkipFileNotScanned)
		return nil
	}
	if strings.Count(text, "\n") != bytes.Count(content, []byte{'\n'}) {
		rep.skipFile(f, FileLinesShifted, SkipLinesShifted)
		return nil
	}
	lines := repofile.EscapeLines(splitLines(text))
	for _, t := range f.targets {
		s.buildTarget(t, lines, budget, rep)
	}
	return nil
}

func (s Slicer) buildTarget(t Target, lines []string, budget int, rep *SliceReport) {
	last := min(len(lines), MaxLine)
	if t.SourceLine < 1 || t.SinkLine < 1 || t.SourceLine > last || t.SinkLine > last {
		rep.NotEvaluated = append(rep.NotEvaluated, NotEvaluated{t.Hypothesis, SkipLineRange})
		return
	}
	hint, ok := s.hintLines(t.Hint)
	if !ok {
		rep.NotEvaluated = append(rep.NotEvaluated, NotEvaluated{t.Hypothesis, SkipHintRefused})
		return
	}
	fl := slicePicks(lines, t.SourceLine, t.SinkLine)
	r := renderSlice(sliceHead{t.Class, t.SourceLine, t.SinkLine, hint}, lines, belowMaxLine(fl.lines), budget)
	rep.Slices = append(rep.Slices, Slice{
		Hypothesis: t.Hypothesis,
		Text:       r.text,
		Shown:      r.shown,
		Partial:    r.partial || fl.partial,
		Redactions: s.Redactor.MarkerCounts(r.text),
		Tier:       s.Tier,
		Hinted:     len(hint) > 0,
		Sink:       lines[t.SinkLine-1],
	})
}

// hintLines redacts and escapes a hint like a file, so the HINT block
// holds only redact.File output. An empty hint gives no lines; one over
// MaxHintBytes or MaxHintLines, or one redact.File refuses, is not ok.
func (s Slicer) hintLines(hint string) ([]string, bool) {
	if hint == "" {
		return nil, true
	}
	if len(hint) > MaxHintBytes || len(splitLines(hint)) > MaxHintLines {
		return nil, false
	}
	text, err := s.Redactor.File([]byte(hint))
	if err != nil {
		return nil, false
	}
	return repofile.EscapeLines(splitLines(text)), true
}

// belowMaxLine drops lines Project could never accept as evidence.
func belowMaxLine(picks []int) []int {
	out := picks[:0:0]
	for _, n := range picks {
		if n <= MaxLine {
			out = append(out, n)
		}
	}
	return out
}

// redactSkip maps a redact.File error to the file's reason, and reports
// whether the run must stop: only ErrRunFull holds for every later call.
func redactSkip(err error) (gateway.SkipReason, bool) {
	switch {
	case errors.Is(err, redact.ErrRunFull):
		return gateway.SkipRunFull, true
	case errors.Is(err, redact.ErrFileTooLarge):
		return gateway.SkipTooLarge, false
	case errors.Is(err, redact.ErrLineTooLong):
		return gateway.SkipLineTooLong, false
	}
	return gateway.SkipRedactFailed, false
}

// splitLines splits redacted text into lines without their line ends, so
// line n of the result is line n of the file.
func splitLines(text string) []string {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}

func (r *SliceReport) skipFile(f fileTargets, file gateway.SkipReason, h SkipReason) {
	r.NotScanned = append(r.NotScanned, gateway.NotScanned{Path: f.path, Reason: file})
	r.skipTargets(f, h)
}

func (r *SliceReport) skipTargets(f fileTargets, reason SkipReason) {
	for _, t := range f.targets {
		r.NotEvaluated = append(r.NotEvaluated, NotEvaluated{t.Hypothesis, reason})
	}
}

// stop lists the file that stopped the run and every later one as not
// scanned, with their hypotheses, and marks the report incomplete.
func (r *SliceReport) stop(rest []fileTargets) {
	r.Incomplete = true
	for _, f := range rest {
		r.skipFile(f, gateway.SkipRunFull, SkipRunFull)
	}
}
