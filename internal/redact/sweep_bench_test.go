package redact

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// emailFragment holds n distinct email addresses that no other fragment
// holds: each one becomes a new value in the run's map.
func emailFragment(id, n int) string {
	var b strings.Builder
	for j := range n {
		fmt.Fprintf(&b, "contact user%dx%d@example.com today\n", id, j)
	}
	return b.String()
}

// BenchmarkSweepGrowth redacts one fragment after a run has already seen
// many fragments of distinct values. The time per fragment must not grow
// with the number of values seen (issue #69).
func BenchmarkSweepGrowth(b *testing.B) {
	const perFragment = 1500
	probe := emailFragment(-1, perFragment)
	for _, seen := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("seen=%d", seen*perFragment), func(b *testing.B) {
			r := newRedactor(b)
			for i := range seen {
				mustRedact(b, r, emailFragment(i, perFragment))
			}
			b.SetBytes(int64(len(probe)))
			for b.Loop() {
				mustRedact(b, r, probe)
			}
		})
	}
}

// BenchmarkRedactRepoChunk reports the median time of one Redact call on a
// full-size chunk of the repository's own code, the ordinary input.
func BenchmarkRedactRepoChunk(b *testing.B) {
	chunks := repoChunks(b)
	r := newRedactor(b)
	var times []time.Duration
	for b.Loop() {
		for _, c := range chunks {
			start := time.Now()
			mustRedact(b, r, c)
			times = append(times, time.Since(start))
		}
	}
	slices.Sort(times)
	b.ReportMetric(float64(times[len(times)/2].Nanoseconds()), "median-ns/chunk")
}

// BenchmarkSweepOverflow redacts real code with the overflow list empty and
// full of values that start with "e", the commonest byte of code: each is
// checked at every "e" in the text. The crafted case is mostly "e", in runs
// that are known values, so it adds none.
func BenchmarkSweepOverflow(b *testing.B) {
	code := repoChunks(b)[0]
	for _, tt := range []struct {
		n     int
		chunk string
	}{{0, code}, {maxOverflowValues, code}, {maxOverflowValues, fill("eeeeeeee ")}} {
		n, chunk := tt.n, tt.chunk
		b.Run(fmt.Sprintf("overflow=%d/crafted=%t", n, chunk != code), func(b *testing.B) {
			r := newRedactor(b)
			for i := range maxWindowValues + n {
				storeOutsideCall(r.state, strings.Repeat("e", minSweepLen+i))
			}
			b.SetBytes(int64(len(chunk)))
			for b.Loop() {
				mustRedact(b, r, chunk)
			}
		})
	}
}

// overflowFull returns a Redactor whose run holds runs of "e" of every
// length from minSweepLen up: the first fill the one window they share, the
// rest the whole overflow list, so every "e" of a text checks them all.
func overflowFull(tb testing.TB) *Redactor {
	tb.Helper()
	r := newRedactor(tb)
	for i := range maxWindowValues + maxOverflowValues {
		storeOutsideCall(r.state, strings.Repeat("e", minSweepLen+i))
	}
	return r
}

// oneByteRuns is a file at MaxFileBytes of lines that are each the longest
// run overflowFull knows: every shorter run matches everywhere in it, and the
// line is a known value, so the call adds none (issue #106).
func oneByteRuns() []byte {
	line := strings.Repeat("e", minSweepLen+maxWindowValues+maxOverflowValues-1) + "\n"
	return []byte(strings.Repeat(line, MaxFileBytes/len(line)))
}

// shortRuns is a file at MaxFileBytes of the shortest known run between
// blanks: every "e" checks every known run, and only the shortest matches.
func shortRuns() []byte {
	line := strings.Repeat(strings.Repeat("e", minSweepLen)+" ", 100) + "\n"
	return []byte(strings.Repeat(line, MaxFileBytes/len(line)))
}

// BenchmarkFileOverflowFull times File at MaxFileBytes with the overflow list
// empty and full: on oneByteRuns, which match most (issue #106), and on
// shortRuns, which make every known run compute a hash at every "e".
func BenchmarkFileOverflowFull(b *testing.B) {
	for _, tt := range []struct {
		shape string
		full  bool
	}{{"runs", false}, {"runs", true}, {"short runs", true}} {
		file := oneByteRuns()
		if tt.shape == "short runs" {
			file = shortRuns()
		}
		full := tt.full
		b.Run(fmt.Sprintf("%s/overflow full=%t", tt.shape, full), func(b *testing.B) {
			r := newRedactor(b)
			if full {
				r = overflowFull(b)
			}
			b.SetBytes(int64(len(file)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := r.File(file); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
