package discover

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// escapeLines makes every file line inert before it is costed or shown.
// It is the rule of internal/reader/escape.go, which discover may not
// import (both are layer 4).
// A carriage return, form feed, vertical tab, NEL, line or paragraph
// separator, terminal escape or bidi control could make a repository line
// render as a second line, so it could pass for a "N| " code line or a
// FILE header. Each such rune becomes a visible escape: \xNN below
// U+0100, otherwise a backslash, "u" and four hex digits. Tabs stay, since
// they carry indentation. Bytes that are not UTF-8 become \xNN.
func escapeLines(lines []string) []string {
	for i, l := range lines {
		lines[i] = escapeLine(l)
	}
	return lines
}

func escapeLine(s string) string {
	if !needsEscape(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case inert(r):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
		i += size
	}
	return b.String()
}

// needsEscape is the fast path: most code lines are printable ASCII.
func needsEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 0x80 || c < 0x20 && c != '\t' || c == 0x7f {
			return true
		}
	}
	return false
}

// inert reports whether r can be shown as is: not a control or format
// rune and not a line or paragraph separator.
func inert(r rune) bool {
	if r == '\t' {
		return true
	}
	return !unicode.IsControl(r) && !unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}
