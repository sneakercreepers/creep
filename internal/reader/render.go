package reader

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// sliceBudget is the most tokens each tier's user turn may take: the
// HYPOTHESIS line, the numbered CODE lines and the truncation notes. Smaller
// tiers get less, because their context is smaller. Tokens are counted as
// bytes, as in promptBudget. Raising a budget is a reviewed change to this
// table; prompts_test.go checks system prompt, schema and user turn together.
var sliceBudget = map[Tier]int{
	TierS: 2048,
	TierM: 4096,
	TierL: 8192,
}

// Notes reader adds to a truncated slice. Every code line starts with its
// number and "| ", so no repository line can pass for one of these.
const (
	sliceCutNote = "[slice truncated: some lines not shown]\n"
	lineCutNote  = " [line truncated]"
)

// lineCapDivisor sets the longest line a slice shows to budget/lineCapDivisor,
// so the sink and handler lines always fit, whatever their length.
const lineCapDivisor = 8

// rendered is a user turn and what it shows.
type rendered struct {
	text    string
	shown   []LineRange
	partial bool
}

// renderSlice writes the user turn for one hypothesis within budget bytes.
// picks are line numbers, most important first; lines are kept in that
// order until the next one does not fit, then shown in file order. Any
// line left out or cut makes the slice partial and adds a note, so a slice
// over budget is truncated, never dropped.
func renderSlice(c Class, source, sink int, lines []string, picks []int, budget int) rendered {
	head := fmt.Sprintf("HYPOTHESIS: %s, source line %d, sink line %d\nCODE:\n", c, source, sink)
	lineCap := budget / lineCapDivisor
	used := len(head) + len(sliceCutNote)
	var kept []int
	partial := false
	for _, n := range dedupe(picks) {
		text, cut := cutLine(lines[n-1], lineCap)
		cost := numberedLen(n, text)
		if used+cost > budget {
			partial = true
			break
		}
		used += cost
		partial = partial || cut
		kept = append(kept, n)
	}
	slices.Sort(kept)
	return rendered{text: writeSlice(head, lines, kept, lineCap, partial), shown: shownRanges(kept), partial: partial}
}

func writeSlice(head string, lines []string, kept []int, lineCap int, partial bool) string {
	var b strings.Builder
	b.WriteString(head)
	for _, n := range kept {
		text, _ := cutLine(lines[n-1], lineCap)
		b.WriteString(strconv.Itoa(n))
		b.WriteString("| ")
		b.WriteString(text)
		b.WriteByte('\n')
	}
	if partial {
		b.WriteString(sliceCutNote)
	}
	return b.String()
}

// numberedLen is the length of line n as written by writeSlice.
func numberedLen(n int, text string) int {
	return len(strconv.Itoa(n)) + len("| ") + len(text) + 1
}

// cutLine shortens a line over lineCap bytes at a rune boundary and marks
// it. The line is redacted already, so a cut can split a marker but never
// expose a secret.
func cutLine(line string, lineCap int) (string, bool) {
	if len(line) <= lineCap {
		return line, false
	}
	i := lineCap - len(lineCutNote)
	for i > 0 && !utf8.RuneStart(line[i]) {
		i--
	}
	return line[:i] + lineCutNote, true
}

// dedupe drops repeated line numbers, keeping the first, most important one.
func dedupe(picks []int) []int {
	seen := make(map[int]bool, len(picks))
	out := picks[:0:0]
	for _, n := range picks {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// shownRanges merges sorted line numbers into inclusive ranges, the lines
// Project accepts as evidence.
func shownRanges(sorted []int) []LineRange {
	var out []LineRange
	for _, n := range sorted {
		u := uint32(n) //nolint:gosec // G115: Build keeps every line within 1..MaxLine
		if k := len(out); k > 0 && out[k-1].End+1 == u {
			out[k-1].End = u
			continue
		}
		out = append(out, LineRange{Start: u, End: u})
	}
	return out
}
