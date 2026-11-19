package static

import "bytes"

// MayHoldRoute reports whether an extractor could find a route in src. It is
// a byte test, cheap enough for a whole node_modules, and it errs only toward
// true: false means no extractor can find a route in src, whatever the parse
// would give, so a caller may list the file without parsing it. A language
// with no extractor gets true, so a caller never reads false as "no route" for
// code static cannot read.
//
// Why it holds: every Python route is a decorator whose attribute is route
// or api_route, or an HTTP verb on a receiver the file builds or imports from
// flask or fastapi (pyroutes.go), and import names are identifiers, so the
// raw bytes hold the word "route", "flask" or "fastapi". Every Express route
// needs a receiver built by a callee named express, or a file importing the
// module "express" or "express.*" (jsscope.go, jsroutes.go). A callee is an
// identifier; a module name is a string literal or a "+" chain of them, with
// escape sequences kept as written (jsFile.literalString). So the raw bytes
// hold the word "express", or a quoted first piece of "express" or
// "node:express" followed by "+" (`"ex" /* c */ + "press"`). A word ends at
// any byte that cannot continue an ASCII identifier, so "expression" and
// "router" do not count; a non-ASCII byte counts as an end, the safe side.
// An identifier spelled with a Unicode escape never matches in the
// extractor either, since it compares the text as written.
//
// Cost: one pass per hint, so linear in len(src) (BenchmarkMayHoldRoute).
func MayHoldRoute(lang Language, src []byte) bool {
	switch lang {
	case Python:
		return containsWord(src, pythonRouteWords)
	case JavaScript, TypeScript, TSX:
		return containsWord(src, jsRouteWords) || startsChain(src, jsChainStarts)
	}
	return true
}

var (
	pythonRouteWords = [][]byte{[]byte("route"), []byte("flask"), []byte("fastapi")}
	jsRouteWords     = [][]byte{[]byte("express")}
	jsChainStarts    = quotedPrefixes("express", "node:express")
)

// quotedPrefixes lists every proper, non-empty prefix of each module name
// inside each JavaScript quote: the first piece a "+" chain could start with.
func quotedPrefixes(names ...string) [][]byte {
	var out [][]byte
	for _, name := range names {
		for n := 1; n < len(name); n++ {
			for _, q := range []string{`"`, `'`, "`"} {
				out = append(out, []byte(q+name[:n]+q))
			}
		}
	}
	return out
}

// containsWord reports whether any word occurs not followed by a byte that
// continues an ASCII identifier. What precedes it is not checked, so a
// longer name ending in the word ("myexpress") counts: the safe side.
func containsWord(src []byte, words [][]byte) bool {
	for _, w := range words {
		for rest := src; ; {
			i := bytes.Index(rest, w)
			if i < 0 {
				break
			}
			rest = rest[i+len(w):]
			if len(rest) == 0 || !identByte(rest[0]) {
				return true
			}
		}
	}
	return false
}

func identByte(b byte) bool {
	return b == '_' || b == '$' || '0' <= b && b <= '9' || 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z'
}

// fillerBudget bounds the bytes startsChain may skip, per byte of src.
// Comments can overlap ("/* "e" /* "e" ... */"), so without it the skips
// could cost quadratic time; past it the answer is true, the safe side.
const fillerBudget = 4

// startsChain reports whether any piece occurs followed by "+", past
// whitespace, closing parentheses and comments. Every occurrence is tried,
// even inside what looks like a comment, since a lone quote can make a
// string look like one.
func startsChain(src []byte, pieces [][]byte) bool {
	budget := fillerBudget * (len(src) + 1)
	for _, p := range pieces {
		for rest := src; ; {
			i := bytes.Index(rest, p)
			if i < 0 {
				break
			}
			rest = rest[i+len(p):]
			next := skipFiller(rest)
			if budget -= len(rest) - len(next); budget < 0 {
				return true
			}
			if len(next) > 0 && next[0] == '+' {
				return true
			}
		}
	}
	return false
}

// skipFiller drops leading whitespace, ')' and comments: "//", "<!--" and
// "-->" to the end of the line (Annex B allows the HTML forms in scripts),
// and "/* ... */". Every non-ASCII byte counts as whitespace, since
// JavaScript also allows Unicode spaces there; a '+' is ASCII, so this never
// skips one.
func skipFiller(b []byte) []byte {
	for len(b) > 0 {
		switch {
		case b[0] >= 0x80 || bytes.IndexByte([]byte(" \t\r\n\f\v)"), b[0]) >= 0:
			b = b[1:]
		case bytes.HasPrefix(b, []byte("//")), bytes.HasPrefix(b, []byte("<!--")), bytes.HasPrefix(b, []byte("-->")):
			b = skipPast(b, []byte("\n"))
		case bytes.HasPrefix(b, []byte("/*")):
			b = skipPast(b[2:], []byte("*/"))
		default:
			return b
		}
	}
	return b
}

// skipPast returns what follows the first end in b, or nothing.
func skipPast(b, end []byte) []byte {
	i := bytes.Index(b, end)
	if i < 0 {
		return nil
	}
	return b[i+len(end):]
}
