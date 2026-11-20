package main

import (
	"regexp"
	"strings"
)

// taskItem matches a ticked task-list item, also inside a blockquote, which
// GitHub still renders as a checkbox; group 1 is the item text.
var taskItem = regexp.MustCompile(`^[\s>]*(?:[-*+]|\d{1,9}[.)])\s+\[[xX]\]\s*(.*)$`)

// docsOnlyClaimed reports whether the body ticks the Documentation-only box.
// It reads the raw body, comments included: a parser that guessed a comment
// where GitHub renders text could otherwise hide a ticked box and pass.
func docsOnlyClaimed(body string) bool {
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		m := taskItem.FindStringSubmatch(line)
		if m != nil && isDocsOnlyBox(m[1]) {
			return true
		}
	}
	return false
}

// isDocsOnlyBox ignores emphasis and code marks and case, so formatting the
// box differently cannot hide it.
func isDocsOnlyBox(text string) bool {
	plain := strings.NewReplacer("*", "", "_", "", "`", "").Replace(text)
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(plain)), "documentation-only")
}
