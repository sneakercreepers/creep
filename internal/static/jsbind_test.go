package static

import "testing"

// jsBindCases: each body ends with a sink whose first argument is x (or a
// literal); dynamic is what DynamicArg must say. Every binding that is not
// a simple constant assignment, anywhere in the handler or its closures,
// must make x dynamic (fail closed, as #185 does for Python).
var jsBindCases = []struct {
	name, body string
	dynamic    bool
}{
	{"const literal", `const x = "ls";`, false},
	{"let reassigned to constants", `let x = "a"; if (c) { x = "b"; } else { x = 'c' + 1; }`, false},
	{"chained assignment of a constant", `let x = "b"; let y = "c"; x = y = "a";`, false},
	{"reassigned from the request", `let x = "a"; if (c) { x = req.query.c; }`, true},
	{"template without substitution", "const x = `ls -l`;", false},
	{"template with substitution", "const x = `ls ${d}`;", true},
	{"concatenated constants", `const a = "ls"; const x = a + " -l" + 2;`, false},
	{"declared without a value", `let x; x = "a";`, true},
	{"object destructuring", `const { x } = req.query;`, true},
	{"array destructuring assignment", `let x = "a"; [x] = req.body;`, true},
	{"for-of binding", `for (const x of req.body) {}`, true},
	{"for-in binding", `let x = "a"; for (x in req.body) {}`, true},
	{"catch parameter", `try { f(); } catch (x) {}`, true},
	{"augmented assignment", `let x = "a"; x += req.query.c;`, true},
	{"update expression", `let x = 1; x++;`, true},
	{"rebound in a nested callback", `let x = "a"; req.on("data", (d) => { x = d; });`, true},
	{"nested function declaration", `const x = "a"; const g = () => { function x() {} };`, true},
	{"parameter of a nested function", `const x = "a"; const g = (x) => x;`, true},
	{"module-level constant", ``, true},
	{"with statement", `const x = "a"; with (req.query) { f(); }`, true},
	{"direct eval", `const x = "a"; eval(req.query.c);`, true},
	{"array bound to a name", `const x = ["a"];`, true},
	{"object bound to a name", `const x = { a: "b" };`, true},
	{"cycle", `let x = y; let y = x;`, true},
	{"parenthesized constant", `const x = ("a");`, false},
	{"ternary", `const x = c ? "a" : "b";`, true},
	{"call result", `const x = String("a");`, true},
	{"member read", `const x = req.query.c;`, true},
	{"null and numbers", `const x = null; const y = 1.5;`, false},
}

func TestJSDynamicArgFailsClosed(t *testing.T) {
	for _, c := range jsBindCases {
		t.Run(c.name, func(t *testing.T) {
			src := "const express = require('express');\nconst cp = require('child_process');\nconst app = express();\nconst x = 'mod';\n" +
				"app.get('/x', (req, res) => {\n" + c.body + "\ncp.exec(x);\n});\n"
			g, l := extractFile(t, "app.js", []byte(src))
			if len(g.Sinks) != 1 || g.Sinks[0].DynamicArg != c.dynamic || g.Routes[0].Partial {
				t.Errorf("want dynamic=%v:\n%s", c.dynamic, summarize(g, l))
			}
		})
	}
}

// TestJSFreshLiteralsInSinkCall: an array or object written in the sink call
// itself is constant when every element is; spreads and computed keys are
// not.
func TestJSFreshLiteralsInSinkCall(t *testing.T) {
	for _, c := range []struct {
		arg     string
		dynamic bool
	}{
		{`["ls", "-l", 1]`, false},
		{`{ name: "a", n: 1, "k": true, ok }`, false},
		{`["ls", req.query.c]`, true},
		{`[...req.body]`, true},
		{`{ [k]: "a" }`, true},
		{`{ ...req.body }`, true},
		{`{ a: { b: "c" } }`, false},
		{`{ f() {} }`, true},
	} {
		src := "const express = require('express');\nconst app = express();\n" +
			"app.get('/x', (req, res) => {\nconst ok = 'y';\ncoll.findOne(" + c.arg + ");\n});\n"
		g, l := extractFile(t, "app.js", []byte(src))
		if len(g.Sinks) != 1 || g.Sinks[0].DynamicArg != c.dynamic {
			t.Errorf("%s: want dynamic=%v:\n%s", c.arg, c.dynamic, summarize(g, l))
		}
	}
}
