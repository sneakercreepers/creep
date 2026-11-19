package redact

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Format characters (Unicode category Cf: zero-width spaces and joiners, the
// byte order mark, soft hyphens, bidi controls, tag characters) render as
// nothing, so one inside a token (U+200B after the "gh" of "ghp_...") hides
// it from every rule while the token still reads whole (issue #70).
// Detection and the sweep run again on a matching copy of the text without
// them, and each span maps back onto the original bytes, the format
// characters inside it included. The text sent changes only where it is
// masked.
//
// The original text is searched too: removing a format character joins its
// neighbors, which can break a match that needs a boundary there (a key id
// followed by a zero-width space and a word). So text that holds a format
// character costs two passes; a leading run alone (a byte order mark) joins
// nothing, so then only the text after it is searched.

// isFormat reports whether r is a format character.
func isFormat(r rune) bool { return unicode.Is(unicode.Cf, r) }

// leadingFormat returns the length of the run of format characters that
// starts text.
func leadingFormat(text string) int {
	n := 0
	for n < len(text) {
		r, w := utf8.DecodeRuneInString(text[n:])
		if !isFormat(r) {
			return n
		}
		n += w
	}
	return n
}

// hasFormat reports whether text holds a format character. ASCII bytes are
// skipped without decoding, so ordinary code costs one byte compare each.
func hasFormat(text string) bool {
	for i := 0; i < len(text); {
		if text[i] < utf8.RuneSelf {
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(text[i:])
		if isFormat(r) {
			return true
		}
		i += w
	}
	return false
}

// stripFormat returns text without its format characters and, for each byte
// kept, its offset in text. Invalid UTF-8 decodes to U+FFFD, which is not a
// format character, so it is kept byte for byte.
func stripFormat(text string) (string, []int) {
	var b strings.Builder
	b.Grow(len(text))
	offsets := make([]int, 0, len(text))
	for i := 0; i < len(text); {
		r, w := utf8.DecodeRuneInString(text[i:])
		if !isFormat(r) {
			b.WriteString(text[i : i+w])
			for k := range w {
				offsets = append(offsets, i+k)
			}
		}
		i += w
	}
	return b.String(), offsets
}

// withoutFormat runs find on text and, when text holds format characters
// after its start, on the copy without them, with every span in text offsets.
// A span of the copy covers the original bytes from its first byte to its
// last, so the format characters between them are masked with it.
func withoutFormat(text string, find func(string) []span) []span {
	lead := leadingFormat(text)
	if !hasFormat(text[lead:]) {
		return shiftSpans(find(text[lead:]), lead)
	}
	found := find(text)
	stripped, offsets := stripFormat(text)
	for _, sp := range find(stripped) {
		if sp.start >= sp.end {
			continue
		}
		sp.start, sp.end = offsets[sp.start], offsets[sp.end-1]+1
		found = append(found, sp)
	}
	return found
}

// shiftSpans moves spans found in text[by:] to text offsets.
func shiftSpans(spans []span, by int) []span {
	if by == 0 {
		return spans
	}
	for i := range spans {
		spans[i].start += by
		spans[i].end += by
	}
	return spans
}
