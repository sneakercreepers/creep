package redact

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// MaxInputBytes bounds one Redact call. RE2 is linear, but with a large
// constant. Measured on a 2019 laptop CPU (i7-10510U): a full chunk of
// ordinary code takes about 85 ms (median, BenchmarkRedactRepoChunk); dense
// key assignments with long names take about 0.6 s, held there by the
// restart budget in secretRule.find (BenchmarkRedact, "env keys"); input
// crafted to hold every rule keyword before a long word run makes all ~220
// rules scan it, about 8 s at the cap (BenchmarkRedact, "every keyword").
// Re-masking the values of earlier fragments is linear in the input and does
// not grow with the number of values known (BenchmarkSweepGrowth). Whole
// files go through File, which chunks them.
const MaxInputBytes = 64 << 10

// maxMarkerLen bounds how far Unredact looks for the closing ">".
const maxMarkerLen = 128

// ErrTooLarge is returned for input over MaxInputBytes.
var ErrTooLarge = errors.New("input exceeds redact.MaxInputBytes")

// Redactor redacts the fragments of one run. It keeps the value-to-marker map
// in memory only so that the same value gets the same marker in every
// fragment. It is safe for concurrent use.
//
// The map has no exported field, no encoding method and prints as a fixed
// string, so it cannot be serialized or logged by accident.
type Redactor struct {
	rules []secretRule
	mu    sync.Mutex
	state *runState // behind a pointer: fmt never prints nested pointees
}

type runState struct {
	byValue  map[string]string // original value -> marker
	byMarker map[string]string // marker -> original value
	counters map[string]int    // label -> last number used
	index    sweepIndex        // the values of at least minSweepLen bytes
	bytes    int               // total length of the keys of byValue
	full     bool              // a value could not be stored: the run is over
	call     callShare         // what the current call has stored
}

// span is a byte range of the input to replace; label names the marker kind.
// A guess masks text a rule gave up searching (secretRule.find): it is not a
// found value, so it is not remembered on its own.
type span struct {
	start, end int
	label      string
	guess      bool
}

// New returns a Redactor loaded with the vendored and the local rules.
func New() (*Redactor, error) {
	rules, err := defaultRules()
	if err != nil {
		return nil, fmt.Errorf("redact: load rules: %w", err)
	}
	return &Redactor{rules: rules, state: &runState{
		byValue:  map[string]string{},
		byMarker: map[string]string{},
		counters: map[string]int{},
		index:    newSweepIndex(),
	}}, nil
}

// Format prints a fixed string for every verb so %v, %+v and %#v never
// reveal the map.
func (r *Redactor) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("redact.Redactor{...}"))
}

// Redact returns text with secrets and personal data replaced by markers and
// pre-existing marker-like text escaped. It fails closed on oversized input
// (ErrTooLarge) and once the run's value map is full (ErrRunFull).
func (r *Redactor) Redact(text string) (string, error) {
	if len(text) > MaxInputBytes {
		return "", fmt.Errorf("redact %d bytes: %w", len(text), ErrTooLarge)
	}
	return r.finish(text, r.detect(text))
}

// finish adds the values known from earlier calls to the spans found in
// text, renders the markers and remembers every masked value for later calls.
// If some value cannot be stored, the output is dropped: when the run is full
// it ends, and when only this call's share is used up the call's values are
// forgotten and the run goes on.
func (r *Redactor) finish(text string, found []span) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state.full {
		return "", ErrRunFull
	}
	r.state.call = callShare{}
	found = append(found, r.state.index.find(text)...)
	out := r.state.render(text, mergeSpans(found))
	r.state.rememberParts(text, found)
	switch {
	case r.state.full:
		return "", ErrRunFull
	case r.state.call.over:
		r.state.rollback()
		return "", ErrTooManyValues
	}
	r.state.call = callShare{}
	return out, nil
}

// rememberParts gives a marker to each value that was masked only as part of
// a merged span (a URL password run into an email), so the sweep still masks
// it when it shows up alone in a later fragment.
//
// A private key's body inside the same key with its header is not stored
// again: it would double the bytes an unterminated key costs the run (#105),
// and the key-body detector masks a bare body wherever it shows up.
func (s *runState) rememberParts(text string, found []span) {
	nested := nestedKeys(found)
	for _, sp := range found {
		if sp.label == "" || sp.guess || sp.end-sp.start < minSweepLen {
			continue
		}
		if sp.label == privateKeyLabel && nested[[2]int{sp.start, sp.end}] {
			continue
		}
		s.marker(text[sp.start:sp.end], sp.label)
	}
}

// nestedKeys returns the bounds of each private-key span that lies inside a
// longer one, in one pass over the key spans sorted by start.
func nestedKeys(found []span) map[[2]int]bool {
	var keys []span
	for _, sp := range found {
		if sp.label == privateKeyLabel {
			keys = append(keys, sp)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].start != keys[j].start {
			return keys[i].start < keys[j].start
		}
		return keys[i].end > keys[j].end
	})
	nested := map[[2]int]bool{}
	outer := span{start: -1, end: -1}
	for _, k := range keys {
		if k.end <= outer.end && k.end-k.start < outer.end-outer.start {
			nested[[2]int{k.start, k.end}] = true
			continue
		}
		if k.end > outer.end {
			outer = k
		}
	}
	return nested
}

// detect runs every secret rule and PII detector over text.
func (r *Redactor) detect(text string) []span {
	return append(r.gated(text).find(text), findPrivateKeys(text)...)
}

// detectorSet holds the detectors whose gate opened on some text: the rules
// whose keyword occurs in it and the pattern detectors whose context matches.
// Private keys are not in it: they span lines and are found separately.
type detectorSet struct {
	rules    []secretRule
	patterns []patternDetector
	encoded  []secretRule // URL-shaped rules to run again on decoded separators
}

// gated returns the detectors that apply to text. File gates on the whole
// file, so a keyword or context in one chunk wakes a detector for every chunk.
func (r *Redactor) gated(text string) detectorSet {
	var set detectorSet
	lower := strings.ToLower(text)
	for _, rule := range r.rules {
		if rule.applies(lower) {
			set.rules = append(set.rules, rule)
		}
	}
	set.encoded = r.encodedRules(text)
	for _, list := range [][]patternDetector{credentialDetectors, piiDetectors} {
		for _, d := range list {
			if d.applies(text) {
				set.patterns = append(set.patterns, d)
			}
		}
	}
	return set
}

// find runs the gated detectors over text.
func (s detectorSet) find(text string) []span {
	var found []span
	for _, rule := range s.rules {
		found = append(found, rule.find(text)...)
	}
	for _, d := range s.patterns {
		found = append(found, d.scan(text)...)
	}
	return append(found, s.findEncoded(text)...)
}

// mergeSpans sorts spans and joins overlapping ones, so every secret byte is
// covered even when two rules disagree on the bounds. The most specific label
// (labelRank) names the merged span, so a URL password that runs into an
// email is one secret, and a GitHub token is not called a generic key.
func mergeSpans(spans []span) []span {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	var out []span
	for _, s := range spans {
		last := len(out) - 1
		if last >= 0 && s.start < out[last].end {
			out[last].end = max(out[last].end, s.end)
			if labelRank(s.label) > labelRank(out[last].label) {
				out[last].label = s.label
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

// render writes the escaped text with each span replaced by its marker.
func (s *runState) render(text string, spans []span) string {
	var b strings.Builder
	b.Grow(len(text))
	prev := 0
	for _, sp := range spans {
		writeEscaped(&b, text[prev:sp.start])
		b.WriteString(s.marker(text[sp.start:sp.end], sp.label))
		prev = sp.end
	}
	writeEscaped(&b, text[prev:])
	return b.String()
}

// marker returns the value's marker, assigning the next number for its label
// the first time the value is seen in this run. When the value cannot be
// stored it returns "" and store has marked the run full or the call over:
// the caller drops the output.
func (s *runState) marker(value, label string) string {
	if m, ok := s.byValue[value]; ok {
		return m
	}
	if !s.store(value) {
		return ""
	}
	if label == "" {
		label = secretPrefix + "VALUE"
	}
	s.counters[label]++
	m := "<" + label + "_" + strconv.Itoa(s.counters[label]) + ">"
	s.byValue[value] = m
	s.byMarker[m] = value
	return m
}

// store admits a new value within the call's share and the run's caps and
// indexes it for the sweep, which re-masks it in later fragments even where
// no rule matches it any more (a key reused without its variable name).
func (s *runState) store(value string) bool {
	if s.full || !s.call.admits(value) {
		return false
	}
	if len(s.byValue) >= maxRunValues || s.bytes+len(value) > maxRunBytes {
		s.full = true
		return false
	}
	if len(value) >= minSweepLen && !s.indexValue(value) {
		return false
	}
	s.bytes += len(value)
	s.call.bytes += len(value)
	s.call.added = append(s.call.added, value)
	return true
}

// Unredact restores the original values in text produced by this Redactor,
// for local display only: its output must never be sent to a model. Unknown
// markers stay as they are, and escaped marker-like text gets its original
// spelling back.
func (r *Redactor) Unredact(text string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for {
		i := strings.IndexByte(text, '<')
		if i < 0 {
			b.WriteString(text)
			return b.String()
		}
		b.WriteString(text[:i])
		text = text[i:]
		n := r.state.unredactAt(&b, text)
		text = text[n:]
	}
}

// MarkerCounts counts the markers of this Redactor in text by label, such as
// SECRET_GITHUB_PAT or PII_EMAIL, for egress.log. Only markers this run
// issued count: escaped marker-like text from the repository does not.
func (r *Redactor) MarkerCounts(text string) map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	counts := map[string]int{}
	for {
		i := strings.IndexByte(text, '<')
		if i < 0 {
			return counts
		}
		text = text[i:]
		if label, ok := r.state.markerLabel(text); ok {
			counts[label]++
		}
		text = text[1:]
	}
}

// markerLabel returns the label of the marker issued by this run that starts
// text, if any. The search for ">" is bounded, so counting stays linear.
func (s *runState) markerLabel(text string) (string, bool) {
	end := strings.IndexByte(text[:min(len(text), maxMarkerLen+2)], '>')
	if end < 0 {
		return "", false
	}
	if _, ok := s.byMarker[text[:end+1]]; !ok {
		return "", false
	}
	return text[1:strings.LastIndexByte(text[:end], '_')], true
}

// unredactAt handles the "<" at the start of text and returns how many bytes
// it consumed.
func (s *runState) unredactAt(b *strings.Builder, text string) int {
	rest := text[1:]
	if strings.HasPrefix(rest, escapeTag) && startsReserved(rest[len(escapeTag):]) {
		b.WriteByte('<')
		return 1 + len(escapeTag)
	}
	end := strings.IndexByte(rest, '>')
	if end >= 0 && end < maxMarkerLen {
		if value, ok := s.byMarker[text[:end+2]]; ok {
			b.WriteString(value)
			return end + 2
		}
	}
	b.WriteByte('<')
	return 1
}
