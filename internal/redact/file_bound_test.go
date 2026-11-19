package redact

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"testing"
	"unicode"
	"unicode/utf8"
)

// unbounded stands for a length no finite input bounds.
const unbounded = 1 << 40

// extent bounds the matches of a regex node, in bytes. lead is the longest
// run from the match start through a newline that more of the match follows;
// final is the longest match that ends in a newline. Both are -1 when no
// such newline is possible. A match ending on line L then starts at most lead
// bytes before L's start: a final newline belongs to L itself.
type extent struct {
	min, max, lead, final int
}

func addLen(a, b int) int { return min(a+b, unbounded) }

func mulLen(n, a int) int {
	if n > 0 && a >= unbounded/n {
		return unbounded
	}
	return n * a
}

// measure walks a parsed regex; every bound is an over-estimate.
func measure(re *syntax.Regexp) extent {
	switch re.Op {
	case syntax.OpLiteral:
		return measureLiteral(re)
	case syntax.OpCharClass:
		return classExtent(maxClassRune(re.Rune), classHasNewline(re.Rune))
	case syntax.OpAnyChar:
		return classExtent(unicode.MaxRune, true)
	case syntax.OpAnyCharNotNL:
		return classExtent(unicode.MaxRune, false)
	case syntax.OpCapture:
		return measure(re.Sub[0])
	case syntax.OpConcat:
		return measureConcat(re.Sub)
	case syntax.OpAlternate:
		return measureAlternate(re.Sub)
	case syntax.OpQuest:
		return measureRepeat(measure(re.Sub[0]), 0, 1)
	case syntax.OpStar:
		return measureRepeat(measure(re.Sub[0]), 0, -1)
	case syntax.OpPlus:
		return measureRepeat(measure(re.Sub[0]), 1, -1)
	case syntax.OpRepeat:
		return measureRepeat(measure(re.Sub[0]), re.Min, re.Max)
	}
	return extent{lead: -1, final: -1} // empty-width assertions
}

func classExtent(top rune, newline bool) extent {
	e := extent{min: 1, max: utf8.RuneLen(top), lead: -1, final: -1}
	if newline {
		e.final = e.max
	}
	return e
}

func classHasNewline(ranges []rune) bool {
	for i := 0; i < len(ranges); i += 2 {
		if ranges[i] <= '\n' && '\n' <= ranges[i+1] {
			return true
		}
	}
	return false
}

func maxClassRune(ranges []rune) rune {
	if len(ranges) == 0 {
		return 0
	}
	return ranges[len(ranges)-1]
}

// measureLiteral counts each rune at its longest case-folded encoding (the
// Kelvin sign is a 3-byte "k").
func measureLiteral(re *syntax.Regexp) extent {
	subs := make([]*syntax.Regexp, len(re.Rune))
	for i, r := range re.Rune {
		top := r
		for f := unicode.SimpleFold(r); re.Flags&syntax.FoldCase != 0 && f != r; f = unicode.SimpleFold(f) {
			top = max(top, f)
		}
		subs[i] = &syntax.Regexp{Op: syntax.OpCharClass, Rune: []rune{top, top}}
		if r == '\n' {
			subs[i].Rune = []rune{'\n', '\n'}
		}
	}
	return measureConcat(subs)
}

func measureConcat(subs []*syntax.Regexp) extent {
	parts := make([]extent, len(subs))
	for i, s := range subs {
		parts[i] = measure(s)
	}
	total := extent{lead: -1, final: -1}
	for i, p := range parts {
		before := total.max
		followed := slices.ContainsFunc(parts[i+1:], func(e extent) bool { return e.max > 0 })
		optionalAfter := !slices.ContainsFunc(parts[i+1:], func(e extent) bool { return e.min > 0 })
		if p.lead >= 0 {
			total.lead = max(total.lead, addLen(before, p.lead))
		}
		if p.final >= 0 && followed {
			total.lead = max(total.lead, addLen(before, p.final))
		}
		if p.final >= 0 && optionalAfter {
			total.final = max(total.final, addLen(before, p.final))
		}
		total.min = addLen(total.min, p.min)
		total.max = addLen(total.max, p.max)
	}
	return total
}

func measureAlternate(subs []*syntax.Regexp) extent {
	total := extent{min: unbounded, lead: -1, final: -1}
	for _, s := range subs {
		e := measure(s)
		total = extent{min(total.min, e.min), max(total.max, e.max), max(total.lead, e.lead), max(total.final, e.final)}
	}
	return total
}

// measureRepeat bounds sub{lo,hi}; hi < 0 means no upper bound. A newline
// ending one copy is followed by the next copy.
func measureRepeat(sub extent, lo, hi int) extent {
	copies := hi
	if hi < 0 {
		copies = unbounded
	}
	e := extent{min: mulLen(lo, sub.min), max: mulLen(copies, sub.max), lead: -1, final: -1}
	if copies == 0 {
		return e
	}
	before := mulLen(copies-1, sub.max)
	if sub.lead >= 0 || sub.final >= 0 && copies > 1 {
		e.lead = addLen(before, max(sub.lead, sub.final))
	}
	if sub.final >= 0 {
		e.final = addLen(before, sub.final)
	}
	return e
}

func leadOf(t *testing.T, re *regexp.Regexp) int {
	t.Helper()
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	return measure(parsed).lead
}

// TestChunkOverlapBound derives the bound chunkOverlap documents: for every
// rule and detector, the bytes a match can hold before the start of its last
// line. A rule over it must be in wholeFileRules, which File runs over the
// whole file, and a rule in that list must still need it; a pattern detector
// has no such escape. A rule added upstream with a longer multi-line reach
// fails here.
func TestChunkOverlapBound(t *testing.T) {
	rules, err := defaultRules()
	if err != nil {
		t.Fatal(err)
	}
	longest, whole := 0, 0
	check := func(label string, re *regexp.Regexp, wholeFile bool) {
		lead := leadOf(t, re)
		switch {
		case !wholeFile && lead > chunkOverlap:
			t.Errorf("%s: a match can start %d bytes before its last line, over chunkOverlap", label, lead)
		case wholeFile && lead <= chunkOverlap:
			t.Errorf("%s: reach %d is bounded now; drop it from wholeFileRules", label, lead)
		case !wholeFile:
			longest = max(longest, lead)
		}
	}
	for _, r := range rules {
		check(r.label, r.re, r.wholeFile)
		if r.wholeFile {
			whole++
		}
	}
	if whole != len(wholeFileRules) {
		t.Errorf("%d rules run over the whole file, wholeFileRules lists %d: an id is stale", whole, len(wholeFileRules))
	}
	for _, d := range slices.Concat(credentialDetectors, piiDetectors) {
		check(d.label, d.re, false)
	}
	t.Logf("longest multi-line reach: %d bytes (chunkOverlap %d)", longest, chunkOverlap)
}

func TestMeasure(t *testing.T) {
	tests := []struct {
		re   string
		want extent
	}{
		{`abc`, extent{3, 3, -1, -1}},
		{`a\nb`, extent{3, 3, 2, -1}},
		{`ab\n`, extent{3, 3, -1, 3}},
		{`a\s{0,3}b`, extent{2, 5, 4, -1}},
		{`a\s*b`, extent{2, unbounded, unbounded, -1}},
		{`a[^\n]*\n?`, extent{1, unbounded, -1, unbounded}},
		{`(?i)k`, extent{1, 3, -1, -1}},
		{`(?:x|\n)+`, extent{1, unbounded, unbounded, unbounded}},
	}
	for _, tc := range tests {
		re, err := syntax.Parse(tc.re, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		if got := measure(re); got != tc.want {
			t.Errorf("measure(%q) = %+v, want %+v", tc.re, got, tc.want)
		}
	}
}
