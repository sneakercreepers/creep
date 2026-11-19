package discover

import (
	"bytes"
	_ "embed" // the sink signatures are data in tripwire.tsv
	"fmt"
	"strings"
	"sync"
)

const (
	// MaxTripwireHits caps the candidates one file can add (ADR 0017). A
	// file at the cap is marked TripwireCut, which reports as truncated.
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
	token   []byte
	bounded bool // starts with an identifier byte, so must not follow one
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
	return signature{kind: kind, token: []byte(token), bounded: isIdentByte(token[0]), fixture: cols[2]}, nil
}

// tripwire matches every signature on every line of text, the redacted
// file, and returns one hit per line and sink kind, in line order. cut
// reports that the file reached MaxTripwireHits. Work is linear in the
// file size times the table size: a file at redact.MaxFileBytes takes
// about 15 ms as ordinary code and 0.12 s in the worst shape measured, one
// line of repeated near-misses, on an i7-10510U (BenchmarkTripwire).
func tripwire(rows []signature, text []byte) (hits []hit, cut bool) {
	var line uint32
	for len(text) > 0 {
		line++
		var l []byte
		l, text = nextLine(text)
		for _, k := range lineKinds(rows, l) {
			if len(hits) == MaxTripwireHits {
				return hits, true
			}
			hits = append(hits, hit{line: line, kind: k})
		}
	}
	return hits, false
}

// lineKinds returns each sink kind some signature matches on l, once.
func lineKinds(rows []signature, l []byte) []SinkKind {
	var kinds []SinkKind
	for _, r := range rows {
		if !containsKind(kinds, r.kind) && r.matches(l) {
			kinds = append(kinds, r.kind)
		}
	}
	return kinds
}

// matches reports whether the signature occurs in l at an allowed place.
// Each search resumes after the last occurrence, so it is linear in l.
func (r signature) matches(l []byte) bool {
	for from := 0; from < len(l); {
		i := bytes.Index(l[from:], r.token)
		if i < 0 {
			return false
		}
		at := from + i
		if !r.bounded || at == 0 || !isIdentByte(l[at-1]) {
			return true
		}
		from = at + 1
	}
	return false
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func containsKind(kinds []SinkKind, k SinkKind) bool {
	for _, have := range kinds {
		if have == k {
			return true
		}
	}
	return false
}

// nextLine splits off the first line of b, without its line end, as
// splitLines counts lines.
func nextLine(b []byte) (line, rest []byte) {
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return bytes.TrimSuffix(b, []byte{'\r'}), nil
	}
	return bytes.TrimSuffix(b[:i], []byte{'\r'}), b[i+1:]
}
