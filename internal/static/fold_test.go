package static

import (
	"strings"
	"testing"
	"time"
)

// TestNFKCTableShape: the table is sorted, runs do not overlap, and a run
// of more than one code point maps onto single letters, so foldRune's
// binary search and offset arithmetic hold.
func TestNFKCTableShape(t *testing.T) {
	for i, r := range nfkcASCII {
		switch {
		case r.lo > r.hi || r.to == "" || !isASCII(r.to):
			t.Errorf("entry %d %+v is malformed", i, r)
		case r.lo < r.hi && len(r.to) != 1:
			t.Errorf("run %d %+v maps onto more than one letter", i, r)
		case i > 0 && nfkcASCII[i-1].hi >= r.lo:
			t.Errorf("entry %d %+v overlaps or is out of order", i, r)
		}
	}
}

func TestFoldPython(t *testing.T) {
	tests := map[string]struct{ in, want string }{
		"ascii":                {"route", "route"},
		"fullwidth":            {"ｒｏｕｔｅ", "route"},
		"fullwidth capital":    {"Ｆｌａｓｋ", "Flask"},
		"fullwidth digit":      {"ｖ２", "v2"},
		"fullwidth underscore": {"api＿route", "api_route"},
		"math bold":            {"𝐫𝐨𝐮𝐭𝐞", "route"},
		"math monospace":       {"𝚏𝚊𝚜𝚝𝚊𝚙𝚒", "fastapi"},
		"math sans digit":      {"x𝟢", "x0"},
		"letterlike h":         {"ℎ", "h"},
		"script capital":       {"ℱ", "F"},
		"ligature":             {"ﬂask", "flask"},
		"long s":               {"ſql", "sql"},
		"kelvin":               {"K", "K"},
		"roman numeral":        {"ⅹ", "x"},
		"modifier letter":      {"ʳoute", "route"},
		"subscript":            {"ₑxecute", "execute"},
		"mixed":                {"ｅxｅcute", "execute"},
		"greek stays":          {"αβ", "αβ"},
		"math greek stays":     {"𝛂", "𝛂"},
		"accent stays":         {"café", "café"},
		"invalid utf-8 stays":  {"r\xffoute", "r\xffoute"},
	}
	for name, tt := range tests {
		if got := foldPython(tt.in); got != tt.want {
			t.Errorf("%s: foldPython(%q) = %q, want %q", name, tt.in, got, tt.want)
		}
	}
}

func TestCookJS(t *testing.T) {
	tests := map[string]struct{ in, want string }{
		"plain":               {"express", "express"},
		"unicode four":        {"g\\u0065t", "get"},
		"unicode braces":      {`\u{71}uery`, "query"},
		"leading zeros":       {`\u{000000071}uery`, "query"},
		"hex":                 {`\x65xpress`, "express"},
		"octal":               {`\145xpress`, "express"},
		"octal stops at 0377": {`\4000`, " 00"},
		"identity":            {`\ex\press`, "express"},
		"simple":              {`a\nb\tc`, "a\nb\tc"},
		"continuation LF":     {"ex\\\npress", "express"},
		"continuation CR":     {"ex\\\rpress", "express"},
		"continuation CRLF":   {"ex\\\r\npress", "express"},
		"continuation LS":     {"ex\\" + lineSeparator + "press", "express"},
		"continuation PS":     {"ex\\" + paragraphSeparator + "press", "express"},
		"escaped backslash":   {`\\u0065`, "\\u0065"},
		"short hex":           {`\x6`, "x6"},
		"unclosed braces":     {`\u{65`, "u{65"},
		"empty braces":        {`\u{}`, "u{}"},
		"too large":           {`\u{110000}`, "u{110000}"},
		"trailing backslash":  {`ab\`, `ab\`},
		"non-ascii identity":  {"\\é", "é"},
		"surrogate half":      {`\uD800`, "\U0000FFFD"},
	}
	for name, tt := range tests {
		if got := cookJS(tt.in); got != tt.want {
			t.Errorf("%s: cookJS(%q) = %q, want %q", name, tt.in, got, tt.want)
		}
	}
}

// TestFoldIsLinear: unclosed escapes and long runs of folded runes cost
// linear time, so a hostile file cannot stall the route test.
func TestFoldIsLinear(t *testing.T) {
	inputs := map[string]string{
		"unclosed braces": strings.Repeat(`\u{0000000000`, 1<<18),
		"fullwidth":       strings.Repeat("ｒｏｕｔｅ", 1<<18),
		"backslashes":     strings.Repeat(`\`, 4<<20),
	}
	for name, in := range inputs {
		start := time.Now()
		cookJS(in)
		foldPython(in)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: %v for %d bytes", name, d, len(in))
		}
	}
}
