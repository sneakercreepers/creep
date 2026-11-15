package redact

import "strings"

// A boundary can cut a header or footer line, so the fragment ends in
// "-----END RSA PRIV" or starts with "ATE KEY-----". Such a stub anchors the
// key lines next to it, even a single body line or one shorter than 40
// bytes, which findBodyRuns alone leaves visible (#73).
//
// A stub of a few dashes could be a list item or a decrement in code, so it
// anchors only a chain that holds a full-size body line. A longer stub
// ("-----E" or more, or a header suffix with a letter) anchors a short body
// line on its own.
const (
	pemEndPrefix  = "-----END"
	pemDashes     = "-----"
	strongStubLen = len(pemDashes) + 1
)

// findCutEdges masks the body lines next to a footer stub at the end of the
// text and a header stub at its start.
func findCutEdges(text string, lines []bodyLine) []span {
	if len(lines) < 2 {
		return nil
	}
	var out []span
	if strong, ok := footerStub(text, lines[len(lines)-1]); ok {
		if sp, ok := bodyBeforeFooter(lines, strong); ok {
			out = append(out, sp)
		}
	}
	if strong, ok := headerStub(text, lines[0]); ok {
		if sp, ok := bodyAfterHeader(lines, strong); ok {
			out = append(out, sp)
		}
	}
	return out
}

// footerStub reports whether the last line, which must reach the end of the
// text, is the start of an END line: a prefix of "-----END", or "-----END"
// and header characters. strong is false for a few dashes alone.
func footerStub(text string, last bodyLine) (strong, ok bool) {
	if last.lineEnd != len(text) {
		return false, false
	}
	s := strings.TrimLeft(text[last.lineStart:last.lineEnd], " \t\"'`+")
	if s == "" {
		return false, false
	}
	if len(s) <= len(pemEndPrefix) {
		return len(s) >= strongStubLen, strings.EqualFold(s, pemEndPrefix[:len(s)])
	}
	return true, strings.EqualFold(s[:len(pemEndPrefix)], pemEndPrefix) && headerChars(s)
}

// headerStub reports whether the first line is the end of a BEGIN line: a
// run of header characters ending in "-". strong needs the closing dashes
// and a letter before them ("Y-----"), not dashes alone.
func headerStub(text string, first bodyLine) (strong, ok bool) {
	s := strings.TrimLeft(text[:glueStart(text, 0, first.lineEnd)], " \t")
	if s == "" || s[len(s)-1] != '-' || !headerChars(s) {
		return false, false
	}
	strong = len(s) >= strongStubLen && strings.HasSuffix(s, pemDashes) && strings.Trim(s, "-") != ""
	return strong, true
}

const headerAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-"

// headerChars reports whether s holds only characters of a PEM header line.
func headerChars(s string) bool {
	for i := range len(s) {
		if strings.IndexByte(headerAlphabet, upper(s[i])) < 0 {
			return false
		}
	}
	return true
}

// bodyBeforeFooter covers the body line before the footer stub, the
// full-size lines before it, and a partial line a boundary left at the start.
func bodyBeforeFooter(lines []bodyLine, strong bool) (span, bool) {
	last := len(lines) - 2
	if !isPartial(lines[last]) {
		return span{}, false
	}
	first := last
	for first > 0 && isFullSize(lines[first-1]) {
		first--
	}
	if !strong && first == last && !isFullSize(lines[last]) {
		return span{}, false
	}
	if first == 1 && isPartial(lines[0]) {
		first = 0
	}
	return span{start: lines[first].start, end: lines[last].end, label: privateKeyLabel}, true
}

// bodyAfterHeader covers the body line after the header stub, the
// full-size lines after it, and the short line that ends them.
func bodyAfterHeader(lines []bodyLine, strong bool) (span, bool) {
	if !isPartial(lines[1]) || !strong && !isFullSize(lines[1]) {
		return span{}, false
	}
	last := 1
	for last+1 < len(lines) && isFullSize(lines[last]) && isFullSize(lines[last+1]) {
		last++
	}
	if isFullSize(lines[last]) && last+1 < len(lines) && isPartial(lines[last+1]) {
		last++
	}
	return span{start: lines[1].start, end: lines[last].end, label: privateKeyLabel}, true
}
