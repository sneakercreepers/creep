package static

import (
	"path/filepath"
	"strings"
	"testing"
)

// respellings rewrite a fixture with spellings its runtime reads as the
// original (#259): Python's NFKC identifiers and JavaScript's escapes. Each
// pair is old, new; every old must occur in the fixture.
var respellings = []struct {
	name, golden string
	pairs        []string
}{
	{"fullwidth flask import", "flask_vulnerable", []string{"from flask import", "from ｆｌａｓｋ import"}},
	{"ligature flask import", "flask_vulnerable", []string{"from flask import", "from ﬂask import"}},
	{"fullwidth verb", "flask_vulnerable", []string{"@app.get(", "@app.ｇｅｔ("}},
	{"math bold receiver", "flask_vulnerable", []string{"@app.", "@𝐚𝐩𝐩."}},
	{"fullwidth sink", "flask_vulnerable", []string{".execute(", ".ｅｘｅｃｕｔｅ("}},
	{"fullwidth request", "flask_vulnerable", []string{"request.", "ｒｅｑｕｅｓｔ."}},
	{"everything fullwidth", "flask_vulnerable", []string{"from flask import", "from ｆｌａｓｋ import", "@app.get(", "@ａｐｐ.ｇｅｔ(", "@app.post(", "@ａｐｐ.ｐｏｓｔ("}},
	{"fastapi in math sans", "fastapi_vulnerable", []string{"from fastapi import", "from 𝖿𝖺𝗌𝗍𝖺𝗉𝗂 import"}},
	{"escaped verb", "express_vulnerable", []string{"app.get(", "app.g\\u0065t("}},
	{"braced escape", "express_vulnerable", []string{"app.post(", "app.\\u{70}ost("}},
	{"escaped query", "express_vulnerable", []string{"req.query", "req.\\u0071uery"}},
	{"escaped callee", "express_vulnerable", []string{"express()", "\\u0065xpress()"}},
	{"escaped sink", "express_vulnerable", []string{"exec(`", "\\u0065xec(`"}},
	{"hex module", "express_vulnerable", []string{`require("express")`, `require("\x65xpress")`}},
	{"braced module", "express_vulnerable", []string{`require("express")`, `require("\u{0000065}xpress")`}},
	{"octal module", "express_vulnerable", []string{`require("express")`, `require("\145xpress")`}},
	{"identity escapes", "express_vulnerable", []string{`require("express")`, `require("\ex\press")`}},
	// The continuation adds a line, so a blank line goes to keep the lines.
	{"continued module", "express_vulnerable", []string{`require("express")`, "require(\"ex\\\npress\")", "require(\"mongodb\");\n\n", "require(\"mongodb\");\n"}},
	{"escaped pieces", "express_vulnerable", []string{`require("express")`, `require("\x65x" + "pr\x65ss")`}},
}

func respell(t *testing.T, src string, pairs []string) string {
	t.Helper()
	for i := 0; i < len(pairs); i += 2 {
		if !strings.Contains(src, pairs[i]) {
			t.Fatalf("fixture lost %q", pairs[i])
		}
		src = strings.ReplaceAll(src, pairs[i], pairs[i+1])
	}
	return src
}

// TestRespelledFixturesExtractTheSame (#259): a route, sink, source or
// module name spelled as its runtime reads it extracts the same graph as
// the plain fixture, and the byte test still sees a route, so a planted
// mark cannot hide it (auditor note on #259).
func TestRespelledFixturesExtractTheSame(t *testing.T) {
	for _, r := range respellings {
		t.Run(r.name, func(t *testing.T) {
			path := fixtureNamed(t, r.golden)
			plain := readFixture(t, path)
			src := []byte(respell(t, string(plain), r.pairs))
			name := "app" + filepath.Ext(path)
			want := summarize(extractFile(t, name, plain))
			if got := summarize(extractFile(t, name, src)); got != want {
				t.Errorf("respelled fixture extracts\n%s\nwant\n%s", got, want)
			}
			lang, _ := LanguageForPath(name)
			if !MayHoldRoute(lang, src) {
				t.Error("MayHoldRoute = false for a respelled route")
			}
		})
	}
}

// TestRespelledWordsOnly: with every ASCII route word respelled away, only
// folding or decoding finds it, so the byte test must do both.
func TestRespelledWordsOnly(t *testing.T) {
	tests := map[string]struct {
		lang Language
		src  string
	}{
		"fullwidth route":   {Python, "@bp.ｒｏｕｔｅ(\"/x\")\ndef x():\n    return 'x'\n"},
		"math route":        {Python, "@bp.𝓻𝓸𝓾𝓽𝓮(\"/x\")\ndef x():\n    return 'x'\n"},
		"ligature flask":    {Python, "import ﬂask\n"},
		"escaped word":      {JavaScript, "const app = require(\"\\u0065xpress\")()\n"},
		"escaped callee":    {TypeScript, "\\u{65}xpress()\n"},
		"continued literal": {JavaScript, "require('ex\\\npress')\n"},
	}
	for name, tt := range tests {
		if !MayHoldRoute(tt.lang, []byte(tt.src)) {
			t.Errorf("%s: MayHoldRoute = false", name)
		}
	}
}
