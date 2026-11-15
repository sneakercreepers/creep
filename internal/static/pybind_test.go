package static

import (
	"strings"
	"testing"
)

// dynamicArgCases are handler bodies ending in a call on q. A name is
// constant only if every binding of it in the function is a constant simple
// assignment (#185).
var dynamicArgCases = []struct {
	name    string
	body    string
	dynamic bool
}{
	{"if/else", "if request.args.get('a'):\n    q = request.args['q']\nelse:\n    q = 'SELECT 1'", true},
	{"else branch assigns input", "if x:\n    q = 'SELECT 1'\nelse:\n    q = request.args['q']", true},
	{"try/except", "try:\n    q = request.args['q']\nexcept KeyError:\n    q = 'ls'", true},
	{"tuple target after constant", "q = 'ls'\nq, d = request.args['q'], 1", true},
	{"list target with splat", "q = 'ls'\n[d, *q] = request.args", true},
	{"for target", "q = 'ls'\nfor q in request.args:\n    pass", true},
	{"for tuple target", "q = 'ls'\nfor i, q in items:\n    pass", true},
	{"with as", "q = 'ls'\nwith open(p) as q:\n    pass", true},
	{"with tuple as", "q = 'ls'\nwith ctx() as (q, r):\n    pass", true},
	{"except as", "q = 'ls'\ntry:\n    pass\nexcept Exception as q:\n    pass", true},
	{"walrus", "q = 'ls'\nif (q := request.args['q']):\n    pass", true},
	{"walrus in comprehension", "q = 'ls'\n[(q := v) for v in request.args]", true},
	{"augmented assignment", "q = 'SELECT 1'\nq += ' WHERE 1'", true},
	{"global", "global q\nq = 'ls'", true},
	{"nonlocal", "nonlocal q\nq = 'ls'", true},
	{"rebound by nested nonlocal", "q = 'ls'\ndef inner():\n    nonlocal q\n    q = request.args['q']\ninner()", true},
	{"import as", "q = 'ls'\nimport os as q", true},
	{"from import", "q = 'ls'\nfrom m import q", true},
	{"nested def name", "q = 'ls'\ndef q():\n    pass", true},
	{"nested class name", "q = 'ls'\nclass q:\n    pass", true},
	{"match capture", "q = 'ls'\nmatch request.args:\n    case [q]:\n        pass", true},
	{"loop reassigns after use", "q = 'ls'\nwhile True:\n    db.execute(q)\n    q = request.args['q']", true},
	{"assigned only after the sink (unbound before it)", "pass", false},
	{"module global", "", true},
	{"self cycle", "q = 'a'\nq = q + 'b'", true},
	{"two-name cycle", "a = 'x'\nb = a\na = b\nq = a", true},
	{"constant chain", "a = 'x'\nb = a + 'y'\nq = b", false},
	{"constant in both branches", "if x:\n    q = 'SELECT 1'\nelse:\n    q = 'SELECT 2'", false},
	{"chained assignment", "q = r = 'SELECT 1'", false},
	{"annotated assignment", "q: str = 'SELECT 1'", false},
	{"comprehension variable over-marks, fails closed", "q = 'ls'\n[q for q in request.args]", true},
	{"attribute target does not bind", "q = 'ls'\nself.q = request.args['q']", false},
	{"subscript target does not bind", "q = 'ls'\nd[q] = request.args['q']", false},
}

func TestDynamicArgFailsClosed(t *testing.T) {
	for _, c := range dynamicArgCases {
		t.Run(c.name, func(t *testing.T) {
			src := "import os\nfrom flask import Flask, request\napp = Flask(__name__)\nq = 'module'\n@app.get('/a')\ndef h(p):\n" +
				indent(c.body) + "    db.execute(q)\n    os.system(q)\n"
			if strings.HasPrefix(c.name, "assigned only after") {
				src += "    q = 'ls'\n"
			}
			g, _ := extractSource(t, src)
			if len(g.Sinks) < 2 {
				t.Fatalf("want the two sinks on q, got %+v", g.Sinks)
			}
			for _, s := range g.Sinks[len(g.Sinks)-2:] {
				if s.DynamicArg != c.dynamic {
					t.Errorf("%s DynamicArg = %v, want %v", s.API, s.DynamicArg, c.dynamic)
				}
			}
		})
	}
}

// TestParameterIsDynamic: a parameter is a binding, so a constant default or
// a later constant assignment does not make it constant.
func TestParameterIsDynamic(t *testing.T) {
	for _, params := range []string{"q", "q='ls'", "*q", "**q", "p, /, q", "*, q='x'"} {
		src := "from flask import Flask\napp = Flask(__name__)\n@app.get('/a')\ndef h(" + params + "):\n    q = 'ls'\n    db.execute(q)\n"
		g, _ := extractSource(t, src)
		if len(g.Sinks) != 1 || !g.Sinks[0].DynamicArg {
			t.Errorf("def h(%s): sinks %+v, want one dynamic", params, g.Sinks)
		}
	}
}

func indent(body string) string {
	if body == "" {
		return ""
	}
	return "    " + strings.ReplaceAll(body, "\n", "\n    ") + "\n"
}
