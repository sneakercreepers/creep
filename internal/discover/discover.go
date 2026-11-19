package discover

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/repofile"
)

// purpose labels discovery calls in egress.log.
const purpose = "discover"

// ErrConfig means Run got a Discoverer or paths it cannot use.
var ErrConfig = errors.New("discover: invalid configuration")

// Discoverer runs inventory, the tripwire and model discovery over a
// repository's files.
type Discoverer struct {
	Redactor *redact.Redactor // one per run, shared with the other model calls
	Model    *models.HTTP     // its SendFunc is the gateway in production
	Tier     Tier
	// Seed is a per-run secret that places and names each batch's canary.
	// The run keeps it so --replay rebuilds the same requests. Zero is
	// refused: a known seed would let a file author predict the canary.
	Seed [32]byte
	// Read returns a file's content; the caller opens it without blocking.
	Read func(path string) ([]byte, error)
}

// fileWork is one path while the run builds its Result.
type fileWork struct {
	path    string
	file    File
	hits    []hit
	entries []entryProp
	sinks   []sinkProp
	auth    []Span
}

type entryProp struct {
	lines Span
	kind  EntryKind
}

type sinkProp struct {
	line     uint32
	kind     SinkKind
	entry    Span // the proposed entry's lines; zero for none
	hasEntry bool
}

// run is the state of one Run.
type run struct {
	d       Discoverer
	system  string
	inv     inventoryTable
	trip    []signature
	budget  int // user turn bytes for real files: the batch budget minus the canary
	work    []fileWork
	pending []section
	used    int
	batches uint32   // discovery calls made so far
	stopCov Coverage // set with stop once the model path stopped
	stop    Reason
	err     error
}

// Run classifies every path, matches the tripwire on every source file and
// asks the model about every source file it may send, in batches of whole
// files each with a canary. A file it cannot read or send in full is
// listed with its Coverage and Reason and the run goes on; ErrRunFull, an
// exhausted budget or a failed call stops the model path: later files are
// listed, the Result is Incomplete and the error is returned. The Result
// is valid either way, and tripwire hits are never dropped.
func (d Discoverer) Run(ctx context.Context, paths []string) (Result, error) {
	r, err := d.newRun(paths)
	if err != nil {
		return Result{}, err
	}
	for i := range r.work {
		r.addFile(ctx, i)
	}
	r.flush(ctx)
	res := assemble(r.work)
	res.Incomplete = r.err != nil
	return res, r.err
}

func (d Discoverer) newRun(paths []string) (*run, error) {
	system, err := System(d.Tier)
	if err != nil {
		return nil, err
	}
	if d.Redactor == nil || d.Model == nil || d.Read == nil || d.Seed == [32]byte{} {
		return nil, fmt.Errorf("%w: Redactor, Model, Read and a non-zero Seed are required", ErrConfig)
	}
	if uint64(len(paths)) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: %d paths", ErrConfig, len(paths))
	}
	inv, err := loadInventory()
	if err != nil {
		return nil, err
	}
	trip, err := loadTripwire()
	if err != nil {
		return nil, err
	}
	work := make([]fileWork, len(paths))
	for i, p := range paths {
		work[i] = fileWork{path: p, file: File{ID: FileID(i)}} //nolint:gosec // G115: checked above
	}
	budget := batchBudget[d.Tier] - canarySize()
	return &run{d: d, system: system, inv: inv, trip: trip, budget: budget, work: work}, nil
}

// addFile classifies path i and, for a source file, runs the tripwire and
// queues it for discovery.
func (r *run) addFile(ctx context.Context, i int) {
	w := &r.work[i]
	e := r.inv.classify(w.path, nil)
	if e.Language == 0 && !r.inv.needsContent(w.path) {
		// The name alone says it is not source: never open it.
		w.file.Manifest, w.file.Container = e.Manifest, e.Container
		w.file.Coverage = CoverageNotSource
		return
	}
	content, readErr := r.d.Read(w.path)
	if readErr != nil {
		content = nil
	}
	e = r.inv.classify(w.path, content)
	w.file.Language, w.file.Manifest, w.file.Container = e.Language, e.Manifest, e.Container
	switch {
	case readErr != nil:
		w.fail(CoverageNotRead, ReasonReadFailed)
	case e.Language == 0:
		w.file.Coverage = CoverageNotSource
	case hasNUL(content):
		w.fail(CoverageNotRead, ReasonReadFailed)
	default:
		r.addSource(ctx, i, content)
	}
}

// addSource redacts a source file whole, runs the tripwire on the
// redacted text, and queues the file. Only redact.File output is matched,
// shown or sent.
func (r *run) addSource(ctx context.Context, i int, content []byte) {
	w := &r.work[i]
	text, err := r.d.Redactor.File(content)
	if err != nil {
		r.redactFailed(w, err)
		return
	}
	if strings.Count(text, "\n") != bytes.Count(content, []byte{'\n'}) {
		w.fail(CoverageNotRead, ReasonLinesShifted)
		return
	}
	w.hits, w.file.TripwireCut = tripwire(r.trip, []byte(text))
	switch {
	case r.stop != ReasonNone:
		w.fail(r.stopCov, r.stop)
	case text == "":
		w.file.Coverage = CoverageReadFull // nothing to read
	default:
		r.queue(ctx, section{work: i, lang: w.file.Language, lines: repofile.EscapeLines(splitLines(text))})
	}
}

// queue adds a section to the pending batch, sending the batch first when
// the section does not fit in it. A file that fits no batch is too_large.
func (r *run) queue(ctx context.Context, s section) {
	size := s.size()
	if size > r.budget {
		r.work[s.work].fail(CoverageNotRead, ReasonTooLarge)
		return
	}
	if len(r.pending) == MaxFilesPerBatch || r.used+size > r.budget {
		r.flush(ctx)
	}
	if r.stop != ReasonNone { // the flush just stopped the model path
		r.work[s.work].fail(r.stopCov, r.stop)
		return
	}
	r.pending = append(r.pending, s)
	r.used += size
}

// redactFailed lists a file redact.File refused. ErrRunFull holds for
// every later call, so it stops the model path; batches already queued
// were redacted in full and are still sent.
func (r *run) redactFailed(w *fileWork, err error) {
	switch {
	case errors.Is(err, redact.ErrRunFull):
		w.fail(CoverageNotRead, ReasonRunFull)
		r.halt(CoverageNotRead, ReasonRunFull, err)
	case errors.Is(err, redact.ErrFileTooLarge):
		w.fail(CoverageNotRead, ReasonTooLarge)
	case errors.Is(err, redact.ErrLineTooLong):
		w.fail(CoverageNotRead, ReasonLineTooLong)
	default:
		w.fail(CoverageNotRead, ReasonRedactFailed)
	}
}

// halt stops the model path: every later source file is listed with cov
// and reason. The first error is the one Run returns.
func (r *run) halt(cov Coverage, reason Reason, err error) {
	if r.stop != ReasonNone {
		return
	}
	r.stopCov, r.stop = cov, reason
	r.err = fmt.Errorf("discover stopped: %w", err)
}

func (w *fileWork) fail(cov Coverage, reason Reason) {
	w.file.Coverage, w.file.Reason = cov, reason
}
