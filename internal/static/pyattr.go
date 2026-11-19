package static

import "strings"

// attrKey splits a decorator's callee, recv.name or getattr(recv, "name"),
// into its object and attribute name (#255 tester M4). A getattr name is a
// string, so it is unescaped (pyUnescape) but not NFKC-folded: Python
// folds identifiers, not strings. known is false when the name is not a
// literal Python can be shown to read as written; ok is false when fn is
// neither form.
func (x *pyExtraction) attrKey(fn *Node) (obj *Node, name string, known, ok bool) {
	switch {
	case fn == nil:
		return nil, "", false, false
	case fn.Type == "attribute":
		return field(fn, "object"), x.file.text(field(fn, "attribute")), true, true
	case fn.Type != "call" || x.file.text(field(fn, "function")) != "getattr":
		return nil, "", false, false
	}
	pos, kw := callArgs(fn)
	if len(pos) < 2 || len(pos) > 3 || len(kw) > 0 {
		return nil, "", false, false
	}
	raw, literal := x.file.literalString(pos[1])
	name, plain := pyUnescape(raw)
	return pos[0], name, literal && plain, true
}

// pyUnescape decodes the escapes a Python string can spell an ASCII name
// with: \xHH, \uHHHH, \UHHHHHHHH, octal and line continuations. Any other
// escape (\N{...} among them) gives ok false, so the caller treats the
// name as unknown instead of guessing.
func pyUnescape(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			i++
			continue
		}
		n, val, ok := pyEscape(s[i+1:])
		if !ok {
			return "", false
		}
		b.WriteString(val)
		i += 1 + n
	}
	return b.String(), true
}

// cookPython is pyUnescape for a whole file, for MayHoldRoute: an escape
// pyEscape does not know stays as written, so a getattr name spelled with
// escapes still shows its route word.
func cookPython(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		n, val, ok := 0, "", false
		if s[i] == '\\' {
			n, val, ok = pyEscape(s[i+1:])
		}
		if !ok {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteString(val)
		i += 1 + n
	}
	return b.String()
}

// pyHexDigits is how many hex digits follow each hex escape letter.
var pyHexDigits = map[byte]int{'x': 2, 'u': 4, 'U': 8}

// pyEscape decodes the escape after a backslash: the bytes it takes and
// its value.
func pyEscape(s string) (int, string, bool) {
	switch {
	case s == "":
		return 0, "", false
	case strings.HasPrefix(s, "\r\n"):
		return 2, "", true
	case s[0] == '\n' || s[0] == '\r':
		return 1, "", true
	case '0' <= s[0] && s[0] <= '7':
		n, v := octalEscape(s)
		return n, v, true
	}
	d, ok := pyHexDigits[s[0]]
	if !ok || len(s) <= d || !allHex(s[1:1+d]) {
		return 0, "", false
	}
	v := hexNumber(s[1 : 1+d])
	if v > 0x10FFFF {
		return 0, "", false
	}
	return 1 + d, string(v), true
}
