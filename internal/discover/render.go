package discover

import (
	"fmt"
	"strconv"
	"strings"
)

// section is one file of a batch as the model sees it: a header, then
// every line of the redacted file behind its number. Every repository line
// starts with "N| " after escaping, so none can pass for a FILE header.
type section struct {
	work  int // index of the file in the run; -1 for the canary
	lang  Language
	lines []string // redacted, escaped, without line ends
}

// header is the line that opens section n, its 0-based file index.
func (s section) header(n int) string {
	return fmt.Sprintf("FILE %d (%s, %d lines):\n", n, s.lang, len(s.lines))
}

// size is the bytes section s takes in a batch. Section numbers have one
// digit (at most maxFiles), so the size does not depend on the position.
func (s section) size() int {
	n := len(s.header(maxFiles - 1))
	for i, l := range s.lines {
		n += len(strconv.Itoa(i+1)) + len("| ") + len(l) + 1
	}
	return n
}

// renderBatch writes the user turn: every section in order.
func renderBatch(sections []section) string {
	var b strings.Builder
	for i, s := range sections {
		b.WriteString(s.header(i))
		for n, l := range s.lines {
			b.WriteString(strconv.Itoa(n + 1))
			b.WriteString("| ")
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// splitLines splits redacted text into lines without their line ends, so
// line n of the result is line n of the file, as reader and the tripwire
// count them.
func splitLines(text string) []string {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}
