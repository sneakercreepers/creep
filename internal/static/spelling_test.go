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
	{"getattr verb", "flask_vulnerable", []string{"@app.get(", `@getattr(app, "get")(`}},
	{"escaped getattr verb", "flask_vulnerable", []string{"@app.get(", `@getattr(app, "g\x65t")(`, "@app.post(", `@getattr(app, "p\u006fst")(`}},
	{"unicode subscript", "express_vulnerable", []string{"app.get(", `app["g\u0065t"](`}},
	{"fullwidth getattr", "flask_vulnerable", []string{"@app.get(", `@ｇｅｔａｔｔｒ(app, "get", None)(`}},
	{"fastapi getattr", "fastapi_vulnerable", []string{"@app.get(", `@getattr(app, "get")(`}},
	{"subscript verb", "express_vulnerable", []string{"app.get(", `app["get"](`}},
	{"template subscript", "express_vulnerable", []string{"app.post(", "app[`post`]("}},
	{"hex subscript", "express_vulnerable", []string{"app.get(", `app["g\x65t"](`}},
	{"concatenated subscript", "express_vulnerable", []string{"app.patch(", `app["pat" + "ch"](`}},
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

// TestComputedVerbIsPartial (#255 tester M4): a verb whose name is not a
// literal, on a known app or router, could be any route, so it is a
// partial route matching every method, never dropped. On a receiver static
// does not know, it is no route, as recv.anything is not.
func TestComputedVerbIsPartial(t *testing.T) {
	const express = "const express = require(\"express\")\nconst app = express()\nconst m = process.env.M\n"
	const flask = "from flask import Flask\napp = Flask(__name__)\nm = 'get'\n"
	tests := []struct {
		name, file, src string
		wantRoutes      int
		wantPartial     bool
	}{
		{"js computed key", "app.js", express + "app[m](\"/x\", (req, res) => res.send(req.query.x))\n", 1, true},
		{"js computed chain", "app.js", express + "app.route(\"/x\")[m]((req, res) => res.send(1))\n", 1, true},
		{"js computed key, unknown receiver", "app.js", express + "other[m](\"/x\", (req, res) => res.send(1))\n", 0, false},
		{"js literal key is not partial", "app.js", express + "app[\"get\"](\"/x\", (req, res) => res.send(1))\n", 1, false},
		{"js computed key, no handler", "app.js", express + "app[m](3000)\n", 0, false},
		{"py getattr name", "app.py", flask + "@getattr(app, m)(\"/x\")\ndef x():\n    return 'x'\n", 1, true},
		{"py getattr named escape", "app.py", flask + "@getattr(app, \"\\N{LATIN SMALL LETTER G}et\")(\"/x\")\ndef x():\n    return 'x'\n", 1, true},
		{"py getattr name, unknown receiver", "app.py", flask + "@getattr(bp, m)(\"/x\")\ndef x():\n    return 'x'\n", 0, false},
		{"py getattr literal is not partial", "app.py", flask + "@getattr(app, \"route\")(\"/x\")\ndef x():\n    return 'x'\n", 1, false},
		{"py getattr string is not folded", "app.py", flask + "@getattr(bp, \"ｒｏｕｔｅ\")(\"/x\")\ndef x():\n    return 'x'\n", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, _ := extractFile(t, tt.file, []byte(tt.src))
			if len(g.Routes) != tt.wantRoutes {
				t.Fatalf("%d routes, want %d", len(g.Routes), tt.wantRoutes)
			}
			for _, r := range g.Routes {
				if r.Partial != tt.wantPartial || tt.wantPartial && r.Methods != methodsAll {
					t.Errorf("route %+v; want partial %v (every method when partial)", r, tt.wantPartial)
				}
			}
		})
	}
}

func TestPyUnescape(t *testing.T) {
	tests := map[string]struct {
		in, want string
		ok       bool
	}{
		"plain":        {"route", "route", true},
		"hex":          {`r\x6fute`, "route", true},
		"short u":      {`r\u006Fute`, "route", true},
		"long u":       {`r\U0000006fute`, "route", true},
		"octal":        {`r\157ute`, "route", true},
		"continuation": {"ro\\\nute", "route", true},
		"named":        {`r\N{LATIN SMALL LETTER O}ute`, "", false},
		"short hex":    {`\x6`, "", false},
		"too large":    {`\U00110000`, "", false},
		"other escape": {`\q`, "", false},
		"trailing":     {`a\`, "", false},
	}
	for name, tt := range tests {
		if got, ok := pyUnescape(tt.in); got != tt.want || ok != tt.ok {
			t.Errorf("%s: pyUnescape(%q) = %q, %v; want %q, %v", name, tt.in, got, ok, tt.want, tt.ok)
		}
	}
}
