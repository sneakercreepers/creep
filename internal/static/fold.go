package static

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// foldRun is one entry of nfkcASCII.
type foldRun struct {
	lo, hi rune
	to     string
}

// foldRune returns the ASCII NFKC form of r, if it has one.
func foldRune(r rune) (string, bool) {
	i := sort.Search(len(nfkcASCII), func(i int) bool { return nfkcASCII[i].hi >= r })
	if i == len(nfkcASCII) || r < nfkcASCII[i].lo {
		return "", false
	}
	run := nfkcASCII[i]
	if run.lo == run.hi {
		return run.to, true
	}
	return string(rune(run.to[0]) + r - run.lo), true
}

// foldPython spells s the way Python reads it as an identifier, so a route,
// sink or auth name written with fullwidth or mathematical letters matches
// (#259). Only code points whose NFKC form is ASCII change; other bytes,
// invalid UTF-8 included, stay as written. NFKC could only compose what
// is left into other non-ASCII text, which matches no ASCII name either.
func foldPython(s string) string {
	if isASCII(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if to, ok := foldRune(r); ok && r != utf8.RuneError {
			b.WriteString(to)
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// JavaScript's two line terminators beyond CR and LF.
const (
	lineSeparator      = "\U00002028"
	paragraphSeparator = "\U00002029"
)

// cookJS returns s with every JavaScript escape sequence replaced by what
// it stands for, so get spelled with a \u escape and "express" spelled
// "\x65xpress" or "ex\<newline>press" match (#259). It reads s from left
// to right, as the tokenizer reads a string or an identifier; an escape it
// does not know stands for its own character, as in sloppy-mode strings.
func cookJS(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		n, val := jsEscape(s[i+1:])
		b.WriteString(val)
		i += 1 + n
	}
	return b.String()
}

var jsSimpleEscapes = map[byte]string{'b': "\b", 'f': "\f", 'n': "\n", 'r': "\r", 't': "\t", 'v': "\v"}

// jsEscape decodes the escape after a backslash in s: the bytes it takes
// and its value. A line continuation stands for nothing.
func jsEscape(s string) (int, string) {
	c := s[0]
	switch {
	case c == 'u':
		return unicodeEscape(s)
	case c == 'x' && len(s) >= 3 && hexValue(s[1]) >= 0 && hexValue(s[2]) >= 0:
		return 3, string(rune(hexValue(s[1])<<4 | hexValue(s[2])))
	case strings.HasPrefix(s, "\r\n"):
		return 2, ""
	case c == '\r' || c == '\n':
		return 1, ""
	case strings.HasPrefix(s, lineSeparator) || strings.HasPrefix(s, paragraphSeparator):
		return 3, ""
	case '0' <= c && c <= '7':
		return octalEscape(s)
	}
	if v, ok := jsSimpleEscapes[c]; ok {
		return 1, v
	}
	_, size := utf8.DecodeRuneInString(s)
	return size, s[:size]
}

// unicodeEscape decodes u followed by four hex digits or by {hex}, which
// may have any number of leading zeros. It reads only the hex digits, so a
// string of unclosed escapes costs linear time.
func unicodeEscape(s string) (int, string) {
	if len(s) >= 5 && allHex(s[1:5]) {
		return 5, string(rune(hexNumber(s[1:5])))
	}
	if len(s) < 2 || s[1] != '{' {
		return 1, "u"
	}
	end := 2
	for end < len(s) && hexValue(s[end]) >= 0 {
		end++
	}
	digits := strings.TrimLeft(s[2:end], "0")
	if end == 2 || end == len(s) || s[end] != '}' || len(digits) > 6 || hexNumber(digits) > utf8.MaxRune {
		return 1, "u"
	}
	return end + 1, string(rune(hexNumber(digits)))
}

// octalEscape decodes a legacy octal escape: up to three digits, at most
// 0377.
func octalEscape(s string) (int, string) {
	v, n := 0, 0
	for n < len(s) && n < 3 && '0' <= s[n] && s[n] <= '7' && v*8+int(s[n]-'0') <= 0377 {
		v = v*8 + int(s[n]-'0')
		n++
	}
	return n, string(rune(v))
}

func hexValue(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c-'a') + 10
	case 'A' <= c && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if hexValue(s[i]) < 0 {
			return false
		}
	}
	return true
}

func hexNumber(s string) int {
	v := 0
	for i := 0; i < len(s); i++ {
		v = v<<4 | hexValue(s[i])
	}
	return v
}
