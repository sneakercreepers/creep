package redact

import (
	"sort"
	"strings"
)

// labelRank orders the labels of overlapping spans: the merged span takes the
// highest. A rule that knows the secret's format beats one that only saw a
// key name, the password detector beats the generic key rule, any secret
// beats PII, and anything beats the unlabelled sweep.
func labelRank(label string) int {
	switch {
	case label == "":
		return 0
	case strings.HasPrefix(label, "PII_"):
		return 1
	case label == genericLabel:
		return 2
	case label == passwordLabel:
		return 3
	}
	return 4
}

// outranks reports whether label a names a merged span before label b. A tie
// of rank goes to the label that sorts first, so the name never depends on
// the order the detectors ran in or on where File cut the text: File and
// Redact name the same span alike (#71).
func outranks(a, b string) bool {
	if ra, rb := labelRank(a), labelRank(b); ra != rb {
		return ra > rb
	}
	return a < b
}

// merged is one span of mergeSpans' output; from and to bound the run of the
// sorted input spans it joins.
type merged struct {
	span
	from, to int
}

// mergeSpans sorts spans in place and joins overlapping ones, so every secret
// byte is covered even when two rules disagree on the bounds. The label that
// outranks the others names the merged span, so a GitHub token is not called
// a generic key.
func mergeSpans(spans []span) []merged {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	var out []merged
	for i, s := range spans {
		last := len(out) - 1
		if last >= 0 && s.start < out[last].end {
			out[last].end = max(out[last].end, s.end)
			out[last].to = i + 1
			if outranks(s.label, out[last].label) {
				out[last].label = s.label
			}
			continue
		}
		out = append(out, merged{span: s, from: i, to: i + 1})
	}
	return out
}

// render writes the escaped text with each merged span replaced by its
// markers; parts is the sorted input of mergeSpans.
func (s *runState) render(text string, spans []merged, parts []span) string {
	var b strings.Builder
	b.Grow(len(text))
	prev := 0
	for _, m := range spans {
		writeEscaped(&b, text[prev:m.start])
		s.writeMerged(&b, text, m, parts[m.from:m.to])
		prev = m.end
	}
	writeEscaped(&b, text[prev:])
	return b.String()
}

// writeMerged writes the markers of one merged span. A secret that only
// personal data reaches past (a URL password whose tail and host read as an
// email) keeps the marker it has on its own, and the bytes on either side
// get their own markers: the password has one name in every fragment, in
// either order, and Unredact stays exact (#71). Any other merged span is one
// value with one marker. A part the sweep found takes the label of the
// marker its value already has, so an email masked in an earlier call still
// counts as personal data.
func (s *runState) writeMerged(b *strings.Builder, text string, m merged, parts []span) {
	parts = s.storedLabels(text, parts)
	w, ok := secretInsidePII(m, parts)
	if !ok {
		b.WriteString(s.marker(text[m.start:m.end], m.label))
		return
	}
	s.writePiece(b, text, m.start, w.start, parts)
	b.WriteString(s.marker(text[w.start:w.end], w.label))
	s.writePiece(b, text, w.end, m.end, parts)
}

// secretInsidePII returns the longest part carrying the merged span's label
// when that label is a secret's, the part is shorter than the span, and
// every part that reaches past it is personal data.
func secretInsidePII(m merged, parts []span) (span, bool) {
	if labelRank(m.label) < labelRank(genericLabel) {
		return span{}, false
	}
	w := span{start: -1}
	for _, p := range parts {
		if p.label == m.label && (w.start < 0 || p.end-p.start > w.end-w.start) {
			w = p
		}
	}
	if w.start == m.start && w.end == m.end {
		return span{}, false
	}
	for _, p := range parts {
		if (p.start < w.start || p.end > w.end) && !strings.HasPrefix(p.label, "PII_") {
			return span{}, false
		}
	}
	return w, true
}

// storedLabels returns parts with each unlabelled part, a known value the
// sweep found, named by the label of its marker. It copies parts only when
// one needs a label.
func (s *runState) storedLabels(text string, parts []span) []span {
	var out []span
	for i, p := range parts {
		if p.label != "" {
			continue
		}
		m, ok := s.byValue[text[p.start:p.end]]
		if !ok {
			continue
		}
		if out == nil {
			out = append([]span(nil), parts...)
		}
		out[i].label = m[1:strings.LastIndexByte(m, '_')]
	}
	if out == nil {
		return parts
	}
	return out
}

// writePiece writes the marker of text[from:to], named by the best label
// among the parts that overlap it. An empty piece writes nothing.
func (s *runState) writePiece(b *strings.Builder, text string, from, to int, parts []span) {
	if from >= to {
		return
	}
	label := ""
	for _, p := range parts {
		if p.start < to && p.end > from && (label == "" || outranks(p.label, label)) {
			label = p.label
		}
	}
	b.WriteString(s.marker(text[from:to], label))
}
