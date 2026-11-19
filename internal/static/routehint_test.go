package static

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// hiddenExpress rewrites the Express fixture's require("express") so the
// raw bytes never hold the word "express" while the extractor still reads it.
func hiddenExpress(t *testing.T, require string) []byte {
	t.Helper()
	src := readFixture(t, fixtureFiles()[4].path) // express_vulnerable
	out := bytes.Replace(src, []byte(`require("express")`), []byte(require), 1)
	if bytes.Equal(out, src) {
		t.Fatal(`fixture lost require("express")`)
	}
	return out
}

// hiddenRequires are module names built to dodge a byte search, keyed by
// case name. The line-comment cases end the comment with every line
// terminator JavaScript accepts (#255 tester M2).
var hiddenRequires = map[string]string{
	"concatenated":          `require("ex" + "press")`,
	"single quotes":         `require('e' + 'xpress')`,
	"template pieces":       "require(`exp` + `ress`)",
	"node prefix":           `require("node:" + "express")`,
	"split node prefix":     `require("n" + "ode:express")`,
	"block comment":         `require("ex" /* c */ + "press")`,
	"comment ended by LF":   "require(\"ex\" // c\n + \"press\")",
	"comment ended by CR":   "require(\"ex\" // c\r + \"press\")",
	"comment ended by CRLF": "require(\"ex\" // c\r\n + \"press\")",
	"comment ended by LS":   "require(\"ex\" // c + \"press\")",
	"comment ended by PS":   "require(\"ex\" // c + \"press\")",
	"parenthesized":         `require(("ex") + "press")`,
	"three pieces":          `require("e" + "x" + "press")`,
	"empty first":           `require("" + "ex" + "press")`,
	"one piece per rune":    `require("e" + "x" + "p" + "r" + "e" + "s" + "s")`,
	"unicode space":         "require(\"ex\" + \"press\")",
}

// TestMayHoldRouteNeverMissesARoute (#213 tester M1, #255 tester M2): a
// proven vendor file is listed unparsed only when MayHoldRoute is false, so
// it must be true for every file the extractor finds a route in. The same
// payloads run through the extractor, as a first-party file would, and
// through the byte test; each hidden form must still extract, so the case
// is real.
func TestMayHoldRouteNeverMissesARoute(t *testing.T) {
	type sample struct {
		name, file string
		src        []byte
	}
	var samples []sample
	for _, f := range fixtureFiles() {
		name := f.golden + map[bool]string{true: ".py", false: ".js"}[strings.HasPrefix(f.golden, "f")]
		if f.golden == "express_ts" {
			name = "app.ts"
		}
		samples = append(samples, sample{f.golden, name, readFixture(t, f.path)})
	}
	for name, require := range hiddenRequires {
		samples = append(samples, sample{name, "app.js", hiddenExpress(t, require)}, sample{name + " in a declaration", "app.d.ts", hiddenExpress(t, require)})
	}
	samples = append(samples,
		sample{"imported blueprint", "views.py", []byte("from .bp import bp\n\n@bp.route(\"/x\")\ndef x():\n    return 'x'\n")},
		sample{"imported fastapi verb", "api.py", []byte("from fastapi import APIRouter\nr = APIRouter()\n\n@r.get(\"/x\")\ndef x():\n    return 1\n")},
		sample{"aliased flask", "a.py", []byte("import flask as f\napp = f.Flask(__name__)\n\n@app.get(\"/x\")\ndef x():\n    return 'x'\n")},
	)
	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) {
			g, _ := extractFile(t, s.file, s.src)
			if len(g.Routes) == 0 {
				t.Fatalf("the extractor found no route, so the case proves nothing")
			}
			lang, _ := LanguageForPath(s.file)
			if !MayHoldRoute(lang, s.src) {
				t.Errorf("MayHoldRoute = false for a file with %d routes", len(g.Routes))
			}
		})
	}
}

// TestMayHoldRouteSkipsLibraryCode: library code with no route token is
// skippable; comments and strings count like code, so a token anywhere
// keeps the file; a language static cannot read is never skippable.
func TestMayHoldRouteSkipsLibraryCode(t *testing.T) {
	tests := []struct {
		name string
		lang Language
		src  string
		want bool
	}{
		{"js library", JavaScript, "module.exports = function add(a, b) { return a + b; };\n", false},
		{"js strings that only start like a piece", JavaScript, `var k = "end", m = 'nope', n = ` + "`expected`;\n", false},
		{"js longer word", JavaScript, "/** Parses an expression; see expressjs. */\n", false},
		{"ts types", TypeScript, "export type Point = { x: number; y: number };\n", false},
		{"js piece in its own literal", JavaScript, `var k = "e";` + "\n", true},
		{"js piece in a comment", JavaScript, `// say "ex" here` + "\n", true},
		{"js piece cut by LF", JavaScript, "var k = \"ex\n", true},
		{"js piece cut by CR", JavaScript, "var k = 'ex\r", true},
		{"js piece cut by LS", JavaScript, "var k = 'ex ", true},
		{"js piece cut by PS", JavaScript, "var k = `ex ", true},
		{"js piece at the end", JavaScript, `var k = "nod`, true},
		{"js name in a comment", JavaScript, "// works with express\n", true},
		{"js name in a hyphenated word", JavaScript, "// see @types/express-serve-static-core\n", true},
		{"js global callee", JavaScript, "const app = express();\n", true},
		{"js name at the end", JavaScript, "x = express", true},
		{"js name before non-ASCII", JavaScript, "express ()\n", true},
		{"python library", Python, "def add(a, b):\n    return a + b\n", false},
		{"python decorator", Python, "@property\ndef x(self):\n    return 1\n", false},
		{"python router word", Python, "routers = routes_for(rerouted)\n", false},
		{"python route word", Python, "# reroute\n", true},
		{"python api_route", Python, "@r.api_route(\"/x\")\n", true},
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

// TestMayHoldRouteIsLinear: near-miss pieces on every byte cost one pass
// per piece, not more.
func TestMayHoldRouteIsLinear(t *testing.T) {
	src := []byte(strings.Repeat(`"exx'nox`, 4<<20/8))
	start := time.Now()
	if MayHoldRoute(JavaScript, src) {
		t.Error("near-miss pieces read as a route token")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("MayHoldRoute took %v on 4 MiB", d)
	}
}

func BenchmarkMayHoldRoute(b *testing.B) {
	inputs := map[string][]byte{
		"library 32MiB":     bytes.Repeat([]byte("function f(a){return a*2}\n"), 32<<20/26),
		"near misses 32MiB": []byte(strings.Repeat(`"exx'nox`, 32<<20/8)),
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
