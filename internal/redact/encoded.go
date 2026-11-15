package redact

import (
	"regexp/syntax"
	"strings"
)

// URL-shaped secrets (webhook URLs) are matched by rules written around a
// literal "/". Serializers that escape slashes (PHP json_encode, some Java and
// .NET ones) write "\/", and a URL embedded in a query string has "%2F" and
// "%3A". Rather than a second regex per rule and encoding, the URL-shaped
// rules run again on a copy of the text with those separators decoded, and
// each match maps back onto the original bytes, escapes included, so the
// vendored rules stay byte for byte upstream (issue #151).

// separatorAt returns the separator encoded at text[i] and the width of its
// encoding, or width 0 when none starts there.
func separatorAt(text string, i int) (byte, int) {
	if text[i] == '\\' && i+1 < len(text) && text[i+1] == '/' {
		return '/', 2
	}
	if text[i] != '%' || i+2 >= len(text) {
		return 0, 0
	}
	switch text[i+1 : i+3] {
	case "2F", "2f":
		return '/', 3
	case "3A", "3a":
		return ':', 3
	}
	return 0, 0
}

// hasEncodedSeparator reports whether text holds "\/", "%2F" or "%3A" in
// either case.
func hasEncodedSeparator(text string) bool {
	for i := 0; i < len(text); i++ {
		if _, w := separatorAt(text, i); w > 0 {
			return true
		}
	}
	return false
}

// decodeSeparators returns text with every encoded separator decoded and,
// for each decoded byte, where it starts in text; the extra last entry is
// len(text). So decoded[i:j] comes from text[starts[i]:starts[j]], which
// takes in the whole of every escape inside it.
func decodeSeparators(text string) (string, []int) {
	var b strings.Builder
	b.Grow(len(text))
	starts := make([]int, 0, len(text)+1)
	for i := 0; i < len(text); {
		starts = append(starts, i)
		if c, w := separatorAt(text, i); w > 0 {
			b.WriteByte(c)
			i += w
			continue
		}
		b.WriteByte(text[i])
		i++
	}
	return b.String(), append(starts, len(text))
}

// decodedOnly is decodeSeparators without the offsets, for keyword gates
// over a whole file.
func decodedOnly(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	for i := 0; i < len(text); {
		if c, w := separatorAt(text, i); w > 0 {
			b.WriteByte(c)
			i += w
			continue
		}
		b.WriteByte(text[i])
		i++
	}
	return b.String()
}

// encodedRules returns the URL-shaped rules whose keyword occurs in text once
// its separators are decoded, or none when text has no encoded separator.
func (r *Redactor) encodedRules(text string) []secretRule {
	if !hasEncodedSeparator(text) {
		return nil
	}
	lower := strings.ToLower(decodedOnly(text))
	var out []secretRule
	for _, rule := range r.rules {
		if rule.urlShaped && rule.applies(lower) {
			out = append(out, rule)
		}
	}
	return out
}

// findEncoded runs the URL-shaped rules on text with its separators decoded
// and returns their spans in text offsets.
func (s detectorSet) findEncoded(text string) []span {
	if len(s.encoded) == 0 || !hasEncodedSeparator(text) {
		return nil
	}
	decoded, starts := decodeSeparators(text)
	var out []span
	for _, rule := range s.encoded {
		for _, sp := range rule.find(decoded) {
			sp.start, sp.end = starts[sp.start], starts[sp.end]
			out = append(out, sp)
		}
	}
	return out
}

// hasLiteralSlash reports whether the regex holds a literal "/" outside a
// character class: a URL path separator, which marks the rule URL-shaped.
func hasLiteralSlash(re *syntax.Regexp) bool {
	if re.Op == syntax.OpLiteral && strings.ContainsRune(string(re.Rune), '/') {
		return true
	}
	for _, sub := range re.Sub {
		if hasLiteralSlash(sub) {
			return true
		}
	}
	return false
}
