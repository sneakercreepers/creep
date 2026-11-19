package discover

import (
	"iter"
	"strings"
)

// tableRows yields the whitespace-separated fields of each row of an
// embedded table with its 1-based line number. Blank lines and lines whose
// first field starts with "#" are skipped. Fields hold no blanks, so a
// tripwire pattern spells a blank as \s.
func tableRows(data string) iter.Seq2[int, []string] {
	return func(yield func(int, []string) bool) {
		for i, line := range strings.Split(data, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			if !yield(i+1, fields) {
				return
			}
		}
	}
}
