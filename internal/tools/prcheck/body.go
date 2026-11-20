package main

import (
	"html"
	"regexp"
	"strings"
	"unicode"
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

// htmlTag and linkTarget hide markup GitHub does not render as text.
var (
	htmlTag    = regexp.MustCompile(`<[^>]*>`)
	linkTarget = regexp.MustCompile(`\]\([^)]*\)`)
)

// isDocsOnlyBox compares letters only, after entities, tags and link targets
// are gone, anywhere in the item, so rewording, formatting or prefixing the
// box cannot hide it.
func isDocsOnlyBox(text string) bool {
	plain := linkTarget.ReplaceAllString(htmlTag.ReplaceAllString(html.UnescapeString(text), ""), "")
	letters := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, plain)
	return strings.Contains(letters, "documentationonly")
}
