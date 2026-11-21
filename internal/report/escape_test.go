package report

import (
	"bytes"
	"encoding/json"
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
	}
	for _, tt := range tests {
		if x, y := codeSpan(tt.a), codeSpan(tt.b); x == y {
			t.Errorf("codeSpan(%q) and codeSpan(%q) both render %q", tt.a, tt.b, x)
		}
	}
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
