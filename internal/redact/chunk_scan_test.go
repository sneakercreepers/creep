package redact

import (
	"strings"
	"testing"
)

// scannedBytes is what the chunked detectors read for text: the sum of the
// chunk lengths.
func scannedBytes(text string) int {
	total := 0
	for _, c := range chunkBounds(text) {
		total += c.end - c.start
	}
	return total
}

// Lines near MaxLineBytes once made chunks overlap by up to a whole line,
// so a crafted file of the same size was scanned about 2.5 times as much as
// ordinary code (issue #102). Counting bytes keeps the test exact.
func TestChunkScanIsBounded(t *testing.T) {
	const maxRatio = 1.2
	short := float64(scannedBytes(textWithLines(MaxFileBytes, 100)))
	worst, worstShape := 0.0, [2]int{}
	for a := 1; a <= MaxLineBytes; a += 997 {
		for _, b := range []int{1, 100, 1000, chunkOverlap, 21379, MaxLineBytes - a%2} {
			text := textWithLines(MaxFileBytes, a, b)
			if ratio := float64(scannedBytes(text)) / short; ratio > worst {
				worst, worstShape = ratio, [2]int{a, b}
			}
		}
	}
	alternating := float64(scannedBytes(textWithLines(MaxFileBytes, 1000, 21379))) / short
	t.Logf("alternating 1000/21379: %.3fx short lines; worst %v: %.3fx", alternating, worstShape, worst)
	if worst > maxRatio {
		t.Errorf("lines %v scan %.3fx the bytes of short lines, over %.1fx", worstShape, worst, maxRatio)
	}
}

// BenchmarkFileEveryKeyword measures the worst case documented on
// MaxFileBytes: a file at the cap that wakes every rule, padded with word
// runs, once in short lines and once in the alternating long lines of #102.
func BenchmarkFileEveryKeyword(b *testing.B) {
	head := keywordLines(b)
	shapes := map[string]string{
		"short lines": head + wordLines(MaxFileBytes-len(head), 100),
		"long lines":  head + wordLines(MaxFileBytes-len(head), 1000, 21379),
	}
	for name, text := range shapes {
		b.Run(name, func(b *testing.B) {
			r := newRedactor(b)
			b.SetBytes(int64(len(text)))
			for b.Loop() {
				if _, err := r.File([]byte(text)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// wordLines is textWithLines of word runs, cut to exactly n bytes.
func wordLines(n int, sizes ...int) string {
	return strings.ReplaceAll(textWithLines(n, sizes...), "x", "a")[:n]
}
