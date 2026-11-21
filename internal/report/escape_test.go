package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestCodeSpan(t *testing.T) {
	tests := []struct{ in, want string }{
		{"a.py", "`a.py`"},
		{"", "`  `"},
		{"a`b", "``a`b``"},
		{"`a", "`` `a ``"},
		{"a``b`", "``` a``b` ```"},
		{"a|b", "`a\\|b`"},
		{"x\x1b[2Jy", "`x\\x1b[2Jy`"},
		{"line\nbreak", "`line\\x0abreak`"},
		{"rlo\u202eexe", "`rlo\\u202eexe`"},
		{"zw\u200bj", "`zw\\u200bj`"},
		{"bad\xff", "`bad\\xff`"},
		{"<script>[x](y)", "`<script>[x](y)`"},
		{`back\slash`, "`back\\\\slash`"},
		{`a\u202eb`, "`a\\\\u202eb`"},
		{"a" + string(rune(0x202e)) + "b", "`a\\u202eb`"},
		{"tag\U000E0041.py", "`tag\\U000e0041.py`"},
		{"tag\U000E0041" + "1", "`tag\\U000e00411`"},
		{"pua" + string(rune(0xe004)) + "1", "`pua\\ue0041`"},
		{`\U000e0041`, "`\\\\U000e0041`"},
		{`a\|b`, "`a\\\\\\|b`"},
		{`bad\xff`, "`bad\\\\xff`"},
		{"emoji\U0001F600", "`emoji\U0001F600`"},
		// \x is one byte; a valid rune from U+0080 up is \u, never \x.
		{"c1\u009b", "`c1\\u009b`"},
		{"c1\x9b", "`c1\\x9b`"},
		{"shy\u00ad", "`shy\\u00ad`"},
		{"del\x7f", "`del\\x7f`"},
		// The last \u rune and the edges of the \U range.
		{"nc\uffff", "`nc\\uffff`"},
		{"lang\U000E0001", "`lang\\U000e0001`"},
		{"max\U0010FFFF", "`max\\U0010ffff`"},
		{"half\xed\xa0\x80", "`half\\xed\\xa0\\x80`"},
		{"repl\ufffd", "`repl\ufffd`"},
	}
	for _, tt := range tests {
		if got := codeSpan(tt.in); got != tt.want {
			t.Errorf("codeSpan(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// A name that spells an escape and the rune that escape stands for must
// never render alike, or a reader cannot tell a hostile name from an
// innocent one.
func TestCodeSpanEscapesAreUnambiguous(t *testing.T) {
	tests := []struct{ a, b string }{
		{`a\u202eb`, "a" + string(rune(0x202e)) + "b"},
		{`a\x1bb`, "a\x1bb"},
		{`a\xffb`, "a\xffb"},
		{`a\|b`, "a|b"},
		{`a\U000e0041b`, "a\U000E0041b"},
		{"a" + string(rune(0xe004)) + "1b", "a\U000E0041b"},
		{"a\x9bb", "a\u009bb"},
		{"a\xadb", "a\u00adb"},
		{`a\\b`, `a\b`},
	}
	for _, tt := range tests {
		if x, y := codeSpan(tt.a), codeSpan(tt.b); x == y {
			t.Errorf("codeSpan(%q) and codeSpan(%q) both render %q", tt.a, tt.b, x)
		}
	}
}

// visible must round-trip: decoding its escapes gives back the exact bytes,
// so no two names render alike, and its output holds no raw '|', control,
// format rune or invalid byte. The seeds run with go test; go test -fuzz
// FuzzVisibleRoundTrip ./internal/report searches further.
func FuzzVisibleRoundTrip(f *testing.F) {
	for _, s := range []string{
		"", "a.py", `a\u202eb`, "a\u202eb", "a|b", `a\|b`, `\`, `\\`, "\x9b", "\u009b",
		"\xad", "\u00ad", "\x7f", "\n", "\xff", "\xed\xa0\x80", "\ufffd", "\uffff",
		"\U000E0041", "\ue0041", "\U0010FFFF", "\U0001F600", "`a``b`", "<b>[x](y)",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := visible(s)
		back, err := unvisible(out)
		if err != nil || back != s {
			t.Fatalf("visible(%q) = %q decodes to %q, %v", s, out, back, err)
		}
	})
}

// unvisible decodes visible's escapes and refuses any raw rune visible must
// have escaped.
func unvisible(s string) (string, error) {
	var b strings.Builder
	for s != "" {
		r, size := utf8.DecodeRuneInString(s)
		if r == '\\' {
			n, err := unescapeOne(&b, s)
			if err != nil {
				return "", err
			}
			s = s[n:]
			continue
		}
		if r == '|' || (r == utf8.RuneError && size == 1) || (r != ' ' && (!unicode.IsPrint(r) || unicode.Is(unicode.Cf, r))) {
			return "", fmt.Errorf("raw %U left unescaped", r)
		}
		b.WriteString(s[:size])
		s = s[size:]
	}
	return b.String(), nil
}

// unescapeOne writes the byte or rune the escape at the start of s stands
// for and returns the escape's length.
func unescapeOne(b *strings.Builder, s string) (int, error) {
	if len(s) < 2 {
		return 0, errors.New("trailing backslash")
	}
	if s[1] == '\\' || s[1] == '|' {
		b.WriteByte(s[1])
		return 2, nil
	}
	width := map[byte]int{'x': 2, 'u': 4, 'U': 8}[s[1]]
	if width == 0 || len(s) < 2+width {
		return 0, fmt.Errorf("bad escape in %q", s)
	}
	v, err := strconv.ParseUint(s[2:2+width], 16, 4*width) // 4 bits per hex digit bounds v
	if err != nil {
		return 0, fmt.Errorf("bad escape in %q: %w", s, err)
	}
	if s[1] == 'x' {
		b.WriteByte(byte(v)) //nolint:gosec // G115: ParseUint bounds v to 8 bits
	} else {
		b.WriteRune(rune(v)) //nolint:gosec // G115: ParseUint bounds v to 32 bits
	}
	return 2 + width, nil
}

// No hostile path may leave a raw control, format rune or invalid byte in
// any format, or a line break that could start new Markdown.
func TestRenderedOutputIsInert(t *testing.T) {
	for ext, out := range render(t, newTestReport(t, sampleInput(t, true))) {
		if !utf8.Valid(out) {
			t.Errorf("%s: invalid UTF-8", ext)
		}
		for i, r := range string(out) {
			if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
				t.Errorf("%s: raw %U at byte %d", ext, r, i)
			}
		}
	}
}

func TestControlAndFormatRunesEscapedInJSON(t *testing.T) {
	raw := "a" + string([]rune{0x202e, 0xE0041, 0x9b, 0x7f, 0xe9})
	got := escapeInert([]byte("{\n" + `  "p": "` + raw + `"}`))
	want := "{\n" + `  "p": "a` + `\u202e\udb40\udc41\u009b\u007f` + string(rune(0xe9)) + `"}`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	var v map[string]string
	if err := json.Unmarshal(got, &v); err != nil || v["p"] != raw {
		t.Errorf("escaped JSON decodes to %q, %v", v["p"], err)
	}
}

func TestURIPath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"src/app.py", "src/app.py"},
		{"a b#c?d%e", "a%20b%23c%3Fd%25e"},
		{"C:\\x", "C%3A%5Cx"},
		{"é\xff", "%C3%A9%FF"},
		{"javascript:alert(1)", "javascript%3Aalert%281%29"},
	}
	for _, tt := range tests {
		got := uriPath(tt.in)
		if got != tt.want {
			t.Errorf("uriPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if strings.ContainsAny(got, ": ") || bytes.ContainsAny([]byte(got), "?#") {
			t.Errorf("uriPath(%q) = %q is not a plain relative path", tt.in, got)
		}
	}
}
