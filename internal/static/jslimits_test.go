package static

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

const jsHeader = "const express = require('express');\nconst cp = require('child_process');\nconst app = express();\n"

func jsExtractor(lim extractLimits) *Extractor { return &Extractor{lim: lim} }

func defaultLimits() extractLimits {
	return extractLimits{routes: maxFileRoutes, constVisits: maxConstVisits, scanVisits: maxScanVisits}
}

func extractWith(t testing.TB, lim extractLimits, src string) (Graph, Locations) {
	t.Helper()
	tree, err := testParser(t).Parse(context.Background(), JavaScript, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	e := jsExtractor(lim)
	if err := e.AddJavaScript("app.js", tree, []byte(src)); err != nil {
		t.Fatal(err)
	}
	return e.Graph(), e.Locations()
}

func TestJSExtractCaps(t *testing.T) {
	t.Run("routes per file", func(t *testing.T) {
		lim := defaultLimits()
		lim.routes = 3
		g, _ := extractWith(t, lim, jsHeader+strings.Repeat("app.get('/x', (req, res) => {});\n", 5))
		if len(g.Routes) != 3 || !g.Files[0].Truncated {
			t.Errorf("routes=%d truncated=%v", len(g.Routes), g.Files[0].Truncated)
		}
	})
	t.Run("sinks per route, helper counted once", func(t *testing.T) {
		src := jsHeader + "function h() { cp.exec(x); }\napp.get('/x', (req, res) => {\n" +
			strings.Repeat("h();\n", 50) + strings.Repeat("cp.exec(x);\n", maxRouteSinks+10) + "});\n"
		g, _ := extractWith(t, defaultLimits(), src)
		if len(g.Sinks) != maxRouteSinks || !g.Files[0].Truncated || !g.Routes[0].Partial {
			t.Errorf("sinks=%d truncated=%v", len(g.Sinks), g.Files[0].Truncated)
		}
	})
	t.Run("long prefix, path and handler name are capped", func(t *testing.T) {
		long := strings.Repeat("p", 3*maxPathBytes)
		// Short lines keep the average line length under the minified cutoff.
		src := jsHeader + "const r = express.Router();\nfunction " + long + "(req, res) {}\nr.get('/" + long + "', " + long + ");\napp.use('/" + long + "', r);\n" +
			strings.Repeat("//\n", 200)
		_, l := extractWith(t, defaultLimits(), src)
		if len(l.Routes) != 1 || len(l.Routes[0].Path) != maxPathBytes || len(l.Routes[0].Handler) != maxHandlerBytes {
			t.Fatalf("routes %+v", l.Routes)
		}
	})
	t.Run("mount chain deeper than the cap is dynamic and claims no auth", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(jsHeader + "app.use(requireAuth);\n")
		for i := range maxMountDepth + 2 {
			b.WriteString("const r" + strconv.Itoa(i) + " = express.Router();\n")
		}
		b.WriteString("r" + strconv.Itoa(maxMountDepth+1) + ".get('/y', (req, res) => {});\n")
		for i := maxMountDepth + 1; i > 0; i-- {
			b.WriteString("r" + strconv.Itoa(i-1) + ".use('/x', r" + strconv.Itoa(i) + ");\n")
		}
		b.WriteString("app.use(r0);\n")
		g, _ := extractWith(t, defaultLimits(), b.String())
		if len(g.Routes) != 1 || !g.Routes[0].DynamicPath || g.Routes[0].Auth != 0 {
			t.Errorf("routes %+v", g.Routes)
		}
	})
	t.Run("mount cycle terminates", func(t *testing.T) {
		src := jsHeader + "const a = express.Router();\nconst b = express.Router();\na.use('/a', b);\nb.use('/b', a);\nb.get('/x', (req, res) => {});\n"
		g, _ := extractWith(t, defaultLimits(), src)
		if len(g.Routes) != 1 || !g.Routes[0].DynamicPath {
			t.Errorf("routes %+v", g.Routes)
		}
	})
	t.Run("scoped guards past the cap claim nothing", func(t *testing.T) {
		src := jsHeader + strings.Repeat("app.use('/other', requireAuth);\n", maxScopedUses) +
			"app.use('/x', requireAuth);\napp.get('/x/y', (req, res) => {});\napp.get('/other/y', (req, res) => {});\n"
		g, _ := extractWith(t, defaultLimits(), src)
		if len(g.Routes) != 2 || g.Routes[0].Auth != 0 || g.Routes[1].Auth != AuthMiddleware {
			t.Errorf("routes %+v", g.Routes)
		}
	})
}

// TestJSHostileShapes: shapes a hostile file can use to make extraction
// slow or deep must stay linear, iterative and capped.
func TestJSHostileShapes(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		check func(Graph, Locations) bool
	}{
		{"long route chain", jsHeader + "app.route('/c')" + strings.Repeat("\n.get((req, res) => {})", maxFileRoutes+100) + ";\n",
			func(g Graph, _ Locations) bool { return len(g.Routes) == maxFileRoutes && g.Files[0].Truncated }},
		{"long concatenated path", jsHeader + "app.get('/a'" + strings.Repeat("\n+ 'b'", 2*maxPathBytes) + ", (req, res) => {});\n",
			func(g Graph, l Locations) bool { return len(g.Routes) == 1 && len(l.Routes[0].Path) == maxPathBytes }},
		{"deeply nested middleware arrays", jsHeader + "app.get('/n', " + strings.Repeat("[\n", 5000) + "requireAuth" + strings.Repeat("]\n", 5000) + ", (req, res) => {});\n",
			func(g Graph, _ Locations) bool { return len(g.Routes) == 1 && g.Routes[0].Auth == AuthMiddleware }},
		{"handlers nested in handlers", jsHeader + strings.Repeat("app.get('/n', (req, res) => { cp.exec('a');\n", 1000) + strings.Repeat("});\n", 1000),
			func(g Graph, _ Locations) bool {
				return len(g.Routes) == 1000 && g.Files[0].Truncated && g.Routes[999].Partial
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			g, l := extractWith(t, defaultLimits(), c.src)
			if !c.check(g, l) {
				t.Errorf("routes %d, files %+v", len(g.Routes), g.Files)
			}
			if d := time.Since(start); d > 30*time.Second {
				t.Errorf("took %s", d)
			}
		})
	}
}

// TestJSScanBudgetFailsClosed: past the scan budget a handler's sinks count
// as dynamic, even with a constant argument, since a rebinding may sit in
// the unscanned part, and its route and file are marked partial; the route
// is never dropped.
func TestJSScanBudgetFailsClosed(t *testing.T) {
	src := jsHeader + "app.get('/x', (req, res) => {\nconst q = 'ls';\ncp.exec(q);\n" + strings.Repeat("f();\n", 40) + "});\n"
	for _, c := range []struct {
		budget           int
		dynamic, partial bool
	}{{maxScanVisits, false, false}, {40, true, true}, {1, false, true}} {
		lim := defaultLimits()
		lim.scanVisits = c.budget
		g, l := extractWith(t, lim, src)
		sinksOK := len(g.Sinks) == 1 && g.Sinks[0].DynamicArg == c.dynamic
		if c.budget == 1 {
			sinksOK = len(g.Sinks) == 0 // cut before the call
		}
		if len(g.Routes) != 1 || !sinksOK || g.Routes[0].Partial != c.partial || g.Files[0].Truncated != c.partial {
			t.Errorf("budget %d:\n%s", c.budget, summarize(g, l))
		}
	}
}

// TestJSConstBudgetFailsClosed mirrors the Python budget test.
func TestJSConstBudgetFailsClosed(t *testing.T) {
	src := jsHeader + "app.get('/x', (req, res) => {\nconst a = 'l' + 's';\nconst b = a + a + a;\ncp.exec(b + b);\n});\n"
	for _, c := range []struct {
		budget           int
		dynamic, partial bool
	}{{maxConstVisits, false, false}, {3, true, true}} {
		lim := defaultLimits()
		lim.constVisits = c.budget
		g, l := extractWith(t, lim, src)
		if len(g.Sinks) != 1 || g.Sinks[0].DynamicArg != c.dynamic || g.Routes[0].Partial != c.partial {
			t.Errorf("budget %d:\n%s", c.budget, summarize(g, l))
		}
	}
}

// BenchmarkExtractJavaScript measures extraction alone on a file of many
// routes, each calling a shared helper with sinks.
func BenchmarkExtractJavaScript(b *testing.B) {
	src := jsHeader + "function h(q) {\n" + strings.Repeat("  cp.exec(q);\n", 50) + "}\n" +
		strings.Repeat("app.post('/x/:id', requireAuth, (req, res) => {\n  const q = 'a' + req.params.id;\n  h(q);\n  cp.exec(q);\n});\n", 2000)
	tree, err := testParser(b).Parse(context.Background(), JavaScript, []byte(src))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		if err := NewExtractor().AddJavaScript("a.js", tree, []byte(src)); err != nil {
			b.Fatal(err)
		}
	}
}
