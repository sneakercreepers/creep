package redact

import (
	"regexp"
	"strings"
)

// patternDetector finds one kind of value with a regex written by this
// package (PII and credential shapes the gitleaks rules miss).
//
// valid, when set, rejects candidates whose checksum or structure is wrong,
// which keeps ordinary numbers and code in the input unmasked. when, when set,
// must match somewhere in the input before re runs: it is a cheap gate for
// detectors that only make sense in some context. skip, when set, rejects a
// match by the text before its value (a key that only looks like a
// credential). bare, when set, judges a value its regex's last group
// captured, an unquoted one, in place of valid (judgeBare).
type patternDetector struct {
	label string
	re    *regexp.Regexp
	valid func(string) bool
	when  *regexp.Regexp
	skip  func(match string) bool
	bare  func(key, value, after string) bareVerdict
}

// applies reports whether the context gate, if any, matches text.
func (d patternDetector) applies(text string) bool {
	return d.when == nil || d.when.MatchString(text)
}

// scan returns the spans of valid values, ignoring the context gate: the
// first group that matched, so a pattern can offer quoted and unquoted
// alternatives. Patterns may start with one boundary character; scan pads
// the text with newlines so boundaries also hold at both ends. Each search
// restarts at the end of the previous value, so its trailing boundary
// character can lead the next match ("a@b.io,c@d.io"); every step advances,
// so the scan stays linear, and the literals after a kept bare value are
// read once per line however many values the line holds (tail).
func (d patternDetector) scan(text string) []span {
	padded := "\n" + text + "\n"
	var out []span
	tail := 0
	for pos := 0; pos < len(padded); {
		m := d.re.FindStringSubmatchIndex(padded[pos:])
		if m == nil {
			break
		}
		start, end := firstGroup(m)
		next := pos + max(end, m[0]+1)
		key := padded[pos+m[0] : pos+start]
		bare := d.bare != nil && m[len(m)-2] >= 0
		start, end, pos = pos+start, pos+end, next
		switch {
		case start == end || (d.skip != nil && d.skip(key)):
		case bare:
			out, tail = d.judge(out, padded, key, start, end, tail)
		case d.valid == nil || d.valid(padded[start:end]):
			out = append(out, span{start: start - 1, end: end - 1, label: d.label})
		}
	}
	return out
}

// judge applies bare to the unquoted value padded[start:end]: it masks the
// value, keeps it, or keeps it and masks the literals after it on its line
// that tail has not read yet. It returns the spans and how far the
// literals have been read.
func (d patternDetector) judge(out []span, padded, key string, start, end, tail int) ([]span, int) {
	after := padded[end:min(end+closeWindow, len(padded))]
	if nl := strings.IndexByte(after, '\n'); nl >= 0 {
		after = after[:nl]
	}
	verdict := d.bare(key, padded[start:end], after)
	switch {
	case verdict == maskValue:
		return append(out, span{start: start - 1, end: end - 1, label: d.label}), tail
	case verdict == keepValue, end < tail:
		return out, tail
	case closesString(padded, start, end):
		return out, tail
	}
	from := end
	if verdict == keepLookup {
		from = skipLiteral(padded, end)
	}
	literals, lineEnd := tailLiterals(padded, max(from, tail), d.label)
	return append(out, literals...), lineEnd
}

// firstGroup returns the bounds of the first group that took part in the
// match, else of the whole match.
func firstGroup(m []int) (int, int) {
	for g := 2; g+1 < len(m); g += 2 {
		if m[g] >= 0 {
			return m[g], m[g+1]
		}
	}
	return m[0], m[1]
}
