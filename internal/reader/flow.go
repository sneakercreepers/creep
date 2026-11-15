package reader

import "strings"

const (
	// maxHeaderLines caps the decorators and def continuation lines kept
	// for a handler, so a hostile file cannot make one header unbounded.
	maxHeaderLines = 8
	// maxScanBytes caps how many bytes each of a hypothesis's two backward
	// walks (to the enclosing def, then through its assignments) reads. A
	// file holds many hypotheses, so without it a large file would cost
	// targets × file size; past the cap the slice is partial.
	maxScanBytes = 64 << 10
)

// flow is the lines a hypothesis's slice is built from, most important
// first, as 1-based line numbers.
type flow struct {
	lines   []int
	partial bool // the walk hit maxScanBytes
}

// slicePicks orders the lines to show for a route→sink hypothesis: the sink,
// the handler's def, its decorators and def continuation, the def of the
// function around the sink, then reaching assignments and guards, nearest
// to the sink first. lines are the redacted file's lines; source and sink
// are valid 1-based line numbers.
func slicePicks(lines []string, source, sink int) flow {
	picks := []int{sink, source}
	picks = append(picks, defContinuation(lines, source)...)
	picks = append(picks, decorators(lines, source)...)
	def, found := enclosingDef(lines, sink)
	if def > 0 && def != source {
		picks = append(picks, def)
	}
	reach, partial := reaching(lines, max(def, 1), sink)
	return flow{lines: append(picks, reach...), partial: partial || !found}
}

// decorators returns the decorator lines right above a def, nearest first.
// They hold the route and any auth decorator.
func decorators(lines []string, def int) []int {
	var out []int
	for n := def - 1; n >= 1 && len(out) < maxHeaderLines; n-- {
		if !strings.HasPrefix(strings.TrimSpace(lines[n-1]), "@") {
			break
		}
		out = append(out, n)
	}
	return out
}

// defContinuation returns the lines after a def whose parameters span
// several lines, up to the one that ends with ":". A source line that is
// not a def has none.
func defContinuation(lines []string, def int) []int {
	if !isDef(lines[def-1]) {
		return nil
	}
	var out []int
	for n := def; n < len(lines) && len(out) < maxHeaderLines; n++ {
		if strings.HasSuffix(strings.TrimSpace(lines[n-1]), ":") {
			break
		}
		out = append(out, n+1)
	}
	return out
}

// enclosingDef returns the line of the def whose body holds line sink, or 0
// at module level. found is false when the walk hit maxScanBytes first.
// Blocks are told apart by indentation, as Python does.
func enclosingDef(lines []string, sink int) (def int, found bool) {
	indent, _ := indentOf(lines[sink-1])
	scanned := 0
	for n := sink - 1; n >= 1 && scanned <= maxScanBytes; n-- {
		line := lines[n-1]
		scanned += len(line) + 1
		in, code := indentOf(line)
		if !code || in >= indent {
			continue
		}
		if isDef(line) {
			return n, true
		}
		indent = in
	}
	return 0, scanned <= maxScanBytes
}

// reaching walks back from the sink to line lo and returns the assignments
// that feed a name used on the sink line, transitively, and the guards that
// test such a name, nearest first. It over-approximates: an assignment never
// stops tracking a name, so a branch-dependent value is still followed.
func reaching(lines []string, lo, sink int) ([]int, bool) {
	scanned := 0
	tracked := identifiers(lines[sink-1], map[string]bool{})
	var out []int
	for n := sink - 1; n >= lo; n-- {
		line := lines[n-1]
		if scanned += len(line) + 1; scanned > maxScanBytes {
			return out, true
		}
		if lhs, rhs, ok := assignment(line); ok && mentions(lhs, tracked) {
			identifiers(rhs, tracked)
			out = append(out, n)
			continue
		}
		if isGuard(line) && mentions(line, tracked) {
			out = append(out, guardBody(lines, n, sink)...)
			out = append(out, n)
		}
	}
	return out, false
}

// guardBody returns the first line of a guard's body when it lies before
// the sink: usually the return or abort that makes the guard matter.
func guardBody(lines []string, guard, sink int) []int {
	next := guard + 1
	if next >= sink {
		return nil
	}
	in, _ := indentOf(lines[guard-1])
	if bodyIn, code := indentOf(lines[next-1]); code && bodyIn > in {
		return []int{next}
	}
	return nil
}

// assignment splits a Python assignment, augmented assignment, for or with
// line into its target and value parts.
func assignment(line string) (lhs, rhs string, ok bool) {
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "for ") {
		if i := strings.Index(t, " in "); i > 0 {
			return t[4:i], t[i+4:], true
		}
	}
	if strings.HasPrefix(t, "with ") || strings.HasPrefix(t, "async with ") {
		if i := strings.LastIndex(t, " as "); i > 0 {
			return t[i+4:], t[:i], true
		}
	}
	if i := assignIndex(t); i > 0 {
		return t[:i], t[i+1:], true
	}
	return "", "", false
}

// assignIndex returns the index of the first "=" outside brackets that is
// not part of a comparison, or -1. An augmented operator stays in the
// target part, where it holds no name.
func assignIndex(t string) int {
	depth := 0
	for i := 0; i < len(t); i++ {
		switch c := t[i]; {
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == '=' && depth == 0:
			if i+1 < len(t) && t[i+1] == '=' {
				i++
				continue
			}
			if i > 0 && strings.IndexByte("=!<>", t[i-1]) >= 0 {
				continue
			}
			return i
		}
	}
	return -1
}

// isGuard reports whether line opens a check on a value.
func isGuard(line string) bool {
	t := strings.TrimSpace(line)
	for _, kw := range []string{"if ", "elif ", "while ", "assert "} {
		if strings.HasPrefix(t, kw) {
			return true
		}
	}
	return false
}

// isDef reports whether line starts a function definition.
func isDef(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "def ") || strings.HasPrefix(t, "async def ")
}

// indentOf returns the width of line's leading blanks and whether the line
// holds code, not only blanks or a comment.
func indentOf(line string) (int, bool) {
	t := strings.TrimLeft(line, " \t")
	if t == "" || t[0] == '#' {
		return 0, false
	}
	return len(line) - len(t), true
}

// identifiers adds every ASCII name in s to set and returns set. Names
// inside strings count too, so an f-string's fields are followed.
func identifiers(s string, set map[string]bool) map[string]bool {
	forEachName(s, func(name string) bool {
		set[name] = true
		return true
	})
	return set
}

// mentions reports whether s holds a name in set.
func mentions(s string, set map[string]bool) bool {
	found := false
	forEachName(s, func(name string) bool {
		found = set[name]
		return !found
	})
	return found
}

// forEachName calls fn on each ASCII name in s until fn returns false.
func forEachName(s string, fn func(string) bool) {
	for i := 0; i < len(s); {
		if !isNameStart(s[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(s) && (isNameStart(s[j]) || s[j] >= '0' && s[j] <= '9') {
			j++
		}
		if !fn(s[i:j]) {
			return
		}
		i = j
	}
}

func isNameStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
