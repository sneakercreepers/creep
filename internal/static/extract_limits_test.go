package static

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExtractCaps(t *testing.T) {
	t.Run("routes per file", func(t *testing.T) {
		src := "from flask import Flask\napp = Flask(__name__)\n" + strings.Repeat("@app.get('/x')\ndef f():\n    pass\n", 5)
		tree, err := testParser(t).Parse(context.Background(), Python, []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		e := &Extractor{lim: extractLimits{routes: 3, constVisits: maxConstVisits}}
		if err := e.AddPython("a.py", tree, []byte(src)); err != nil {
			t.Fatal(err)
		}
		if g := e.Graph(); len(g.Routes) != 3 || !g.Files[0].Truncated {
			t.Errorf("routes=%d truncated=%v", len(g.Routes), g.Files[0].Truncated)
		}
	})
	t.Run("sinks per route, helper counted once", func(t *testing.T) {
		src := "import os\nfrom flask import Flask\napp = Flask(__name__)\ndef h():\n    os.system(x)\n@app.get('/x')\ndef f():\n" +
			strings.Repeat("    h()\n", 50) + strings.Repeat("    os.system(x)\n", maxRouteSinks+10)
		g, _ := extractSource(t, src)
		if len(g.Sinks) != maxRouteSinks || !g.Files[0].Truncated {
			t.Errorf("sinks=%d truncated=%v", len(g.Sinks), g.Files[0].Truncated)
		}
	})
	t.Run("long prefix and handler name are capped", func(t *testing.T) {
		long := strings.Repeat("p", 3*maxPathBytes)
		src := "from flask import Flask, Blueprint\nbp = Blueprint('b', __name__, url_prefix='/" + long + "')\n@bp.get('/" + long + "')\ndef " + long + "():\n    pass\n"
		_, l := extractSource(t, src)
		if len(l.Routes) != 1 || len(l.Routes[0].Path) != maxPathBytes || len(l.Routes[0].Handler) != maxHandlerBytes {
			t.Errorf("path %d bytes, handler %d bytes", len(l.Routes[0].Path), len(l.Routes[0].Handler))
		}
	})
	t.Run("mount chain deeper than the cap is dynamic", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("from fastapi import APIRouter\n")
		for i := range maxMountDepth + 2 {
			b.WriteString("r" + string(rune('a'+i)) + " = APIRouter(prefix='/x')\n")
			if i > 0 {
				b.WriteString("r" + string(rune('a'+i-1)) + ".include_router(r" + string(rune('a'+i)) + ")\n")
			}
		}
		b.WriteString("@r" + string(rune('a'+maxMountDepth+1)) + ".get('/y')\ndef y():\n    pass\n")
		g, _ := extractSource(t, b.String())
		if len(g.Routes) != 1 || !g.Routes[0].DynamicPath {
			t.Errorf("routes %+v", g.Routes)
		}
	})
}

// assignmentChain builds a handler whose SQL argument is a chain of levels
// assignments, each referencing the previous one fanout times. Without
// memoization DynamicArg would visit fanout^levels nodes.
func assignmentChain(levels, fanout int, leaf string) string {
	var b strings.Builder
	b.WriteString("from flask import Flask\napp = Flask(__name__)\n@app.get('/c')\ndef c():\n")
	b.WriteString("    v0 = " + strings.TrimSuffix(strings.Repeat("'a' + ", fanout-1)+leaf, " + ") + "\n")
	for i := 1; i <= levels; i++ {
		prev := "v" + strconv.Itoa(i-1)
		b.WriteString("    v" + strconv.Itoa(i) + " = " + strings.Repeat(prev+" + ", fanout-1) + prev + "\n")
	}
	b.WriteString("    db.execute(v" + strconv.Itoa(levels) + ")\n")
	return b.String()
}

// TestDynamicArgAssignmentChain is the regression test for exponential
// DynamicArg analysis: 20^6 paths must cost a few hundred visits.
func TestDynamicArgAssignmentChain(t *testing.T) {
	for _, c := range []struct {
		leaf    string
		dynamic bool
	}{{"'a'", false}, {"user", true}} {
		start := time.Now()
		g, _ := extractSource(t, assignmentChain(6, 20, c.leaf))
		if len(g.Sinks) != 1 || g.Sinks[0].DynamicArg != c.dynamic || g.Routes[0].Partial {
			t.Errorf("leaf %s: sinks %+v routes %+v", c.leaf, g.Sinks, g.Routes)
		}
		// Parsing dominates; the unmemoized version took minutes here.
		if d := time.Since(start); d > 30*time.Second {
			t.Errorf("leaf %s: took %s", c.leaf, d)
		}
	}
}

// TestDynamicArgBudgetFailsClosed: past the visit budget a sink is reported
// dynamic and its route and file are marked partial, never dropped.
func TestDynamicArgBudgetFailsClosed(t *testing.T) {
	src := assignmentChain(3, 5, "'a'")
	tree, err := testParser(t).Parse(context.Background(), Python, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		budget           int
		dynamic, partial bool
	}{{maxConstVisits, false, false}, {10, true, true}} {
		e := &Extractor{lim: extractLimits{routes: maxFileRoutes, constVisits: c.budget}}
		if err := e.AddPython("a.py", tree, []byte(src)); err != nil {
			t.Fatal(err)
		}
		g := e.Graph()
		if len(g.Sinks) != 1 || g.Sinks[0].DynamicArg != c.dynamic || g.Routes[0].Partial != c.partial || g.Files[0].Truncated != c.partial {
			t.Errorf("budget %d: sinks %+v routes %+v files %+v", c.budget, g.Sinks, g.Routes, g.Files)
		}
	}
}

// BenchmarkExtractPython measures extraction alone (the parse is done once)
// on a file of many routes, each calling a shared helper with sinks: the
// worst case for helper lookups.
func BenchmarkExtractPython(b *testing.B) {
	src := "from flask import Flask\napp = Flask(__name__)\ndef h(q):\n" + strings.Repeat("    db.execute(q)\n", 50) +
		strings.Repeat("@app.post('/x/<id>')\ndef f(id):\n    q = 'a' + id\n    h(q)\n    db.execute(q)\n", 2000)
	tree, err := testParser(b).Parse(context.Background(), Python, []byte(src))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		if err := NewExtractor().AddPython("a.py", tree, []byte(src)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkExtractAssignmentChain is the DynamicArg worst case: a long chain
// of assignments, each referencing the previous one many times.
func BenchmarkExtractAssignmentChain(b *testing.B) {
	src := assignmentChain(300, 20, "'a'")
	tree, err := testParser(b).Parse(context.Background(), Python, []byte(src))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		if err := NewExtractor().AddPython("a.py", tree, []byte(src)); err != nil {
			b.Fatal(err)
		}
	}
}
