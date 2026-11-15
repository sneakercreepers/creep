package redact

import (
	"regexp/syntax"
	"strings"
)

// restartLimits is what one find may still scan again: line until the
// current line is given up, total until the rest of the text is.
type restartLimits struct{ line, total int }

func newRestartLimits(text string) restartLimits {
	base := max(len(text), minRestartBudgetBase)
	return restartLimits{line: restartBudget * base, total: (restartBudget + 1) * base}
}

// charge counts n bytes scanned again.
func (l *restartLimits) charge(n int) {
	l.line -= n
	l.total -= n
}

// giveUpLine masks text from pos to the end of its line, gives the next
// line as many bytes as it masked and returns where to search next. When a
// match of the rule could start in the masked part and go on to the next
// line, that line is masked too. With the total spent it masks the rest of
// the text instead. The span is a guess, not a found value, so it is never
// remembered on its own.
func (l *restartLimits) giveUpLine(text string, pos int, r secretRule) (span, int) {
	end := len(text)
	if i := strings.IndexByte(text[pos:], '\n'); i >= 0 && l.total > 0 {
		end = pos + i
		if r.crossesLine && danglingAssignment(text, pos, end) {
			end = nextTextLineEnd(text, end)
		}
	}
	l.line = min(end+1-pos, l.total)
	return span{start: pos, end: end, label: r.label, guess: true}, end + 1
}

// Bytes a key's separator may end a line with ("db_password =", "key:",
// `token = "`), and bytes an assignment may start the next line with.
const (
	danglingEnds   = "=:>,|?'\"`"
	danglingStarts = "=:>|?,"
)

// danglingAssignment reports whether the masked text[pos:end] may leave an
// assignment open across the newline at end: it ends in a separator byte,
// or the next line holding text starts with an assignment operator.
func danglingAssignment(text string, pos, end int) bool {
	tail := strings.TrimRight(text[pos:end], " \t\r")
	if tail == "" {
		return false
	}
	if strings.IndexByte(danglingEnds, tail[len(tail)-1]) >= 0 {
		return true
	}
	next := strings.TrimLeft(text[end+1:nextTextLineEnd(text, end)], " \t\r\n")
	return next != "" && strings.IndexByte(danglingStarts, next[0]) >= 0
}

// nextTextLineEnd returns the end of the first line after the newline at nl
// that holds more than blanks, or the end of text.
func nextTextLineEnd(text string, nl int) int {
	for start := nl + 1; start < len(text); {
		end := len(text)
		if i := strings.IndexByte(text[start:], '\n'); i >= 0 {
			end = start + i
		}
		if strings.TrimSpace(text[start:end]) != "" {
			return end
		}
		start = end + 1
	}
	return len(text)
}

// matchesNewline reports whether the regex can match a newline: a class or
// literal that holds one, or any character with the s flag.
func matchesNewline(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpAnyChar:
		return true
	case syntax.OpLiteral:
		return strings.ContainsRune(string(re.Rune), '\n')
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if re.Rune[i] <= '\n' && '\n' <= re.Rune[i+1] {
				return true
			}
		}
	}
	for _, sub := range re.Sub {
		if matchesNewline(sub) {
			return true
		}
	}
	return false
}
