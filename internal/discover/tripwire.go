package discover

import (
	"bytes"
	"cmp"
	_ "embed" // the sink signatures are data in tripwire.tsv
	"fmt"
	"slices"
	"strings"
	"sync"
)

const (
	// MaxTripwireHits caps the candidates one file can add (ADR 0017). A
	// file past the cap is marked TripwireCut, which reports as truncated.
	MaxTripwireHits = 1024
	// maxTripwireRows and the signature bounds are the table limits ADR
	// 0017 fixes, so matching stays linear in file size times table size.
	maxTripwireRows   = 512
	minSignatureBytes = 2
	maxSignatureBytes = 64
)

// signature is one tripwire row.
type signature struct {
	kind    SinkKind
	token   []byte // searched bytes: the row without a call's final "("
	call    bool   // the row ends in "(" after an identifier byte: blanks may come before it
	bounded bool   // starts with an identifier byte, so must not follow one
	fixture string
}

// hit is one tripwire candidate: a line and the kind of sink on it.
type hit struct {
	line uint32
	kind SinkKind
}

//go:embed tripwire.tsv
var tripwireData string

// loadTripwire parses the embedded table once.
var loadTripwire = sync.OnceValues(func() ([]signature, error) {
	return parseTripwire(tripwireData)
})

// parseTripwire reads "<kind> TAB <signature> TAB <fixture>" rows.
func parseTripwire(data string) ([]signature, error) {
	var rows []signature
	for i, line := range strings.Split(data, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		row, err := parseSignature(line)
		if err != nil {
			return nil, fmt.Errorf("tripwire.tsv line %d: %w", i+1, err)
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 || len(rows) > maxTripwireRows {
		return nil, fmt.Errorf("tripwire.tsv: %d rows, want 1 to %d", len(rows), maxTripwireRows)
	}
	return rows, nil
}

func parseSignature(line string) (signature, error) {
	cols := strings.Split(line, "\t")
	if len(cols) != 3 {
		return signature{}, fmt.Errorf("want <kind> TAB <signature> TAB <fixture>, got %d columns", len(cols))
	}
	kind, ok := sinkKindByName(cols[0])
	if !ok {
		return signature{}, fmt.Errorf("unknown kind %q", cols[0])
	}
	token := cols[1]
	if len(token) < minSignatureBytes || len(token) > maxSignatureBytes {
		return signature{}, fmt.Errorf("signature of %d bytes, want %d to %d", len(token), minSignatureBytes, maxSignatureBytes)
	}
	s := signature{kind: kind, token: []byte(token), bounded: isIdentByte(token[0]), fixture: cols[2]}
	if n := len(token); token[n-1] == '(' && isIdentByte(token[n-2]) {
		s.token, s.call = s.token[:n-1], true
	}
	return s, nil
}

// tripwire matches every signature over text, the redacted file, and
// returns one hit per line and sink kind, in line order. cut reports that
// the file had more than MaxTripwireHits. Each row is one forward search
// of the whole file that jumps to the next line after a hit, so work is
// linear in the file size times the table size and does not grow with
// the line count. On an i7-10510U a file at redact.MaxFileBytes takes
// about 17 ms of empty or one-byte lines and up to 0.16 s when every line
// holds a hit or a near-miss (BenchmarkTripwire), below what redact.File
// takes on the same file.
func tripwire(rows []signature, text []byte) (hits []hit, cut bool) {
	for _, r := range rows {
		hits = r.lines(text, hits)
	}
	slices.SortFunc(hits, func(a, b hit) int {
		return cmp.Or(cmp.Compare(a.line, b.line), cmp.Compare(a.kind, b.kind))
	})
	hits = slices.Compact(hits)
	if len(hits) > MaxTripwireHits {
		return hits[:MaxTripwireHits], true
	}
	return hits, false
}

// lines appends a hit for each line the row matches, up to one past the
// cap: a row's later lines cannot be among the file's first
// MaxTripwireHits hits.
func (r signature) lines(text []byte, hits []hit) []hit {
	line, counted := uint32(1), 0
	for from, found := 0, 0; found <= MaxTripwireHits; found++ {
		at := r.next(text, from)
		if at < 0 {
			return hits
		}
		line += uint32(bytes.Count(text[counted:at], []byte{'\n'})) //nolint:gosec // G115: at most redact.MaxFileBytes lines
		counted = at
		hits = append(hits, hit{line: line, kind: r.kind})
		end := bytes.IndexByte(text[at:], '\n')
		if end < 0 {
			return hits
		}
		from = at + end + 1
	}
	return hits
}

// matches reports whether the signature occurs in l at an allowed place.
func (r signature) matches(l []byte) bool { return r.next(l, 0) >= 0 }

// next returns the offset of the first allowed occurrence at or after
// from, or -1. A rejected occurrence resumes one byte later; the blank
// skip of a call stops at the first other byte, which no blank run
// shares with another occurrence, so the search stays linear.
func (r signature) next(text []byte, from int) int {
	for from < len(text) {
		i := bytes.Index(text[from:], r.token)
		if i < 0 {
			return -1
		}
		at := from + i
		if r.allowed(text, at) {
			return at
		}
		from = at + 1
	}
	return -1
}

func (r signature) allowed(text []byte, at int) bool {
	if r.bounded && at > 0 && isIdentByte(text[at-1]) {
		return false
	}
	if !r.call {
		return true
	}
	j := at + len(r.token)
	for j < len(text) && (text[j] == ' ' || text[j] == '\t') {
		j++
	}
	return j < len(text) && text[j] == '('
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
