package static

import "bytes"

// MayHoldRoute reports whether an extractor could find a route in src. It is
// a byte test, cheap enough for a whole node_modules, and it errs only toward
// true: false means no extractor can find a route in src, whatever the parse
// would give, so a caller may list the file without parsing it. A language
// with no extractor gets true, so a caller never reads false as "no route" for
// code static cannot read.
//
// It reads no syntax at all: comments, strings and code count alike, so no
// comment form, line terminator or error-recovered parse can hide a token
// from it (#255 tester M2). Why it holds:
//
//   - Every Python route is a decorator whose attribute is route or
//     api_route, or an HTTP verb on a receiver the file builds or imports
//     from flask or fastapi (pyroutes.go). Import names and attributes are
//     identifiers, so the bytes hold the word "route", "flask" or "fastapi".
//   - Every Express route needs a receiver built by a callee named express,
//     or a file importing the module "express" or "express.*" (jsscope.go,
//     jsroutes.go). A callee is an identifier; a module name is a string
//     literal or a "+" chain of them, with escape sequences kept as written
//     (jsFile.literalString). So the bytes hold the word "express", or a
//     string literal whose whole text is a first piece of "express" or
//     "node:express" (`"ex" + "press"`). A literal's text ends at its quote,
//     at a line break or at the end of the file (an unterminated literal the
//     parser closes), and that is where a piece must end.
//
// A word ends at any byte that cannot continue an ASCII identifier, so
// "expression" and "router" do not count; a non-ASCII byte counts as an
// end, the safe side. An identifier spelled with a Unicode escape never
// matches in the extractor either, since it compares the text as written.
//
// Cost: one pass per word and piece, so linear in len(src)
// (BenchmarkMayHoldRoute).
func MayHoldRoute(lang Language, src []byte) bool {
	switch lang {
	case Python:
		return containsWord(src, pythonRouteWords)
	case JavaScript, TypeScript, TSX:
		return containsWord(src, jsRouteWords) || containsPiece(src, jsFirstPieces)
	}
	return true
}

var (
	pythonRouteWords = [][]byte{[]byte("route"), []byte("flask"), []byte("fastapi")}
	jsRouteWords     = [][]byte{[]byte("express")}
	jsFirstPieces    = quotedPrefixes("express", "node:express")
)

// quotedPiece is an opening quote and the text a literal starts with; the
// literal must end right after it (pieceEnds).
type quotedPiece struct {
	quote byte
	open  []byte
}

// quotedPrefixes lists every proper, non-empty prefix of each module name
// after each JavaScript quote: the first piece a "+" chain could start with.
func quotedPrefixes(names ...string) []quotedPiece {
	var out []quotedPiece
	for _, name := range names {
		for n := 1; n < len(name); n++ {
			for _, q := range []byte{'"', '\'', '`'} {
				out = append(out, quotedPiece{quote: q, open: []byte(string(q) + name[:n])})
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

// containsPiece reports whether a quote and a piece occur where a literal
// could end right after the piece: its own quote, a line break (CR, LF,
// U+2028, U+2029) or the end of src.
func containsPiece(src []byte, pieces []quotedPiece) bool {
	for _, p := range pieces {
		for rest := src; ; {
			i := bytes.Index(rest, p.open)
			if i < 0 {
				break
			}
			rest = rest[i+len(p.open):]
			if pieceEnds(rest, p.quote) {
				return true
			}
		}
	}
	return false
}

func pieceEnds(rest []byte, quote byte) bool {
	switch {
	case len(rest) == 0, rest[0] == quote, rest[0] == '\n', rest[0] == '\r':
		return true
	}
	return bytes.HasPrefix(rest, []byte(" ")) || bytes.HasPrefix(rest, []byte(" "))
}
