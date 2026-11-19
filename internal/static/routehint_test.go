package static

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// hiddenExpress rewrites the Express fixture's require("express") so the
// raw bytes never hold "express" while the extractor still reads it.
func hiddenExpress(t *testing.T, require string) []byte {
	t.Helper()
	src := readFixture(t, fixtureFiles()[4].path) // express_vulnerable
	out := bytes.Replace(src, []byte(`require("express")`), []byte(require), 1)
	if bytes.Equal(out, src) {
		t.Fatal(`fixture lost require("express")`)
	}
	return out
}

// TestMayHoldRouteNeverMissesARoute (#213 tester M1): a proven vendor file
// is listed unparsed only when MayHoldRoute is false, so it must be true for
// every file the extractor finds a route in, including module names built
// to dodge a byte search. Each hidden form is checked to still extract.
func TestMayHoldRouteNeverMissesARoute(t *testing.T) {
	type sample struct {
		name, file string
		src        []byte
		mustRoute  bool // the extractor must find a route, so the case is real
	}
	var samples []sample
	for _, f := range fixtureFiles() {
		name := f.golden + map[bool]string{true: ".py", false: ".js"}[strings.HasPrefix(f.golden, "f")]
		if f.golden == "express_ts" {
			name = "app.ts"
		}
		samples = append(samples, sample{f.golden, name, readFixture(t, f.path), true})
	}
	for name, require := range map[string]string{
		"concatenated":            `require("ex" + "press")`,
		"single quotes":           `require('e' + 'xpress')`,
		"template pieces":         "require(`exp` + `ress`)",
		"node prefix":             `require("node:" + "express")`,
		"split node prefix":       `require("n" + "ode:express")`,
		"block comment":           `require("ex" /* c */ + "press")`,
		"line comment":            "require(\"ex\" // c\n + \"press\")",
		"parenthesized":           `require(("ex") + "press")`,
		"three pieces":            `require("e" + "x" + "press")`,
		"empty first":             `require("" + "ex" + "press")`,
		"unicode space before +":  "require(\"ex\" + \"press\")",
		"decoy comment before it": `"'\"ex\"/*'; " + require("ex" + "press") /* */`,
	} {
		must := name != "unicode space before +" && name != "decoy comment before it"
		samples = append(samples, sample{name, "app.js", hiddenExpress(t, require), must})
	}
	samples = append(samples,
		sample{"imported blueprint", "views.py", []byte("from .bp import bp\n\n@bp.route(\"/x\")\ndef x():\n    return 'x'\n"), true},
		sample{"imported fastapi verb", "api.py", []byte("from fastapi import APIRouter\nr = APIRouter()\n\n@r.get(\"/x\")\ndef x():\n    return 1\n"), true},
	)
	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) {
			g, _ := extractFile(t, s.file, s.src)
			if s.mustRoute && len(g.Routes) == 0 {
				t.Fatalf("the extractor found no route, so the case proves nothing")
			}
			lang, _ := LanguageForPath(s.file)
			if len(g.Routes) > 0 && !MayHoldRoute(lang, s.src) {
				t.Errorf("MayHoldRoute = false for a file with %d routes", len(g.Routes))
			}
		})
	}
}

// TestMayHoldRouteSkipsLibraryCode: library code with no route token is
// skippable, and a language static cannot read never is.
func TestMayHoldRouteSkipsLibraryCode(t *testing.T) {
	tests := []struct {
		name string
		lang Language
		src  string
		want bool
	}{
		{"js library", JavaScript, "module.exports = function add(a, b) { return a + b; };\n", false},
		{"js quoted piece without +", JavaScript, `var k = "e"; var m = { "ex": 1 };` + "\n", false},
		{"js quoted piece then other op", JavaScript, `var k = "ex" - 1; // + later` + "\n", false},
		{"js piece then +", JavaScript, `var k = "e" + 1;` + "\n", true},
		{"js name in a comment", JavaScript, "// works with express\n", true},
		{"js longer word", JavaScript, "/** Parses an expression; see expressjs. */\n", false},
		{"js global callee", JavaScript, "const app = express();\n", true},
		{"js name at the end", JavaScript, "x = express", true},
		{"js name before non-ASCII", JavaScript, "express ()\n", true},
		{"python router word", Python, "routers = routes_for(rerouted)\n", false},
		{"python api_route", Python, "@r.api_route(\"/x\")\n", true},
		{"ts types", TypeScript, "export type Point = { x: number; y: number };\n", false},
		{"python library", Python, "def add(a, b):\n    return a + b\n", false},
		{"python decorator", Python, "@property\ndef x(self):\n    return 1\n", false},
		{"python route word", Python, "# reroute\n", true},
		{"python flask import", Python, "import flask\n", true},
		{"empty", JavaScript, "", false},
		{"no extractor", Language(250), "anything", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MayHoldRoute(tt.lang, []byte(tt.src)); got != tt.want {
				t.Errorf("MayHoldRoute(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

// TestMayHoldRouteIsBounded: overlapping comment openers cannot make the
// chain scan quadratic; past its budget the answer is the safe true.
func TestMayHoldRouteIsBounded(t *testing.T) {
	src := []byte(strings.Repeat(`"e" /* `, 1<<20/7) + "*/")
	start := time.Now()
	if !MayHoldRoute(JavaScript, src) {
		t.Error("a budget-exhausting file reads as route-free")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("MayHoldRoute took %v on 1 MiB", d)
	}
}

func BenchmarkMayHoldRoute(b *testing.B) {
	inputs := map[string][]byte{
		"library 32MiB":      bytes.Repeat([]byte("function f(a){return a*2}\n"), 32<<20/26),
		"comment flood 1MiB": []byte(strings.Repeat(`"e" /* `, 1<<20/7) + "*/"),
	}
	for name, src := range inputs {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(src)))
			for b.Loop() {
				MayHoldRoute(JavaScript, src)
			}
		})
	}
}
