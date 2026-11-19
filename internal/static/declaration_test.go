package static

import (
	"context"
	"strings"
	"testing"
)

// routerDeclaration is shaped like router 2.x's lib/route.d.ts (#255 tester
// M3): "express" in a comment, so MayHoldRoute is true, and call
// signatures with generic defaults on separate lines, which the pinned
// grammar does not parse.
const routerDeclaration = "declare namespace Route {\n" +
	"  // Follow the route parameter inference used by @types/express-serve-static-core.\n" +
	"  type RouteMethod<T, DefaultParams = Params> = {\n" +
	"    <F extends Handler<any> = RequestHandler<DefaultParams>>(handler: HandlerArg<F>, ...handlers: Array<HandlerArg<F>>): T\n" +
	"    <P = DefaultParams>(handler: HandlerArg<RequestHandler<P>>, ...handlers: Array<HandlerArg<RequestHandler<P>>>): T\n" +
	"  }\n" +
	"}\nexport = Route\n"

// brokenRouteCode puts Express code into routerDeclaration where the
// grammar cannot read it, or behind a comment the grammar might end late.
var brokenRouteCode = map[string]string{
	"route in the broken region": strings.Replace(routerDeclaration, "  }\n",
		"  }\n  const app = require(\"express\")()\n  app.get(\"/x\", (q, r) => r.send(q.query.x))\n", 1),
	"require before the broken region": "const app = require(\"ex\" + \"press\")()\n" + routerDeclaration,
	"route after it":                   routerDeclaration + "import express = require(\"express\")\n",
	"comment ended by CR":              "// c\rconst e = require(\"express\")\n" + routerDeclaration,
	"comment ended by LS":              "// c const e = require(\"express\")\n" + routerDeclaration,
	"comment ended by PS":              "// c const e = require(\"express\")\n" + routerDeclaration,
	"block comment closed early":       "/* c */ express() /* d */\n" + routerDeclaration,
}

func TestIsDeclaration(t *testing.T) {
	for name, want := range map[string]bool{
		"lib/route.d.ts": true, "a.D.TS": true, "x.d.mts": true, "x.d.cts": true,
		"route.ts": false, "d.ts": false, "x.d.js": false, "x.dts": false,
	} {
		if got := IsDeclaration(name); got != want {
			t.Errorf("IsDeclaration(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestAddDeclaration: a route-free declaration file under a vendor path is
// vendor even when it does not parse, a route in one is still extracted, and
// nothing else gets the lenience: the same file through AddJavaScript, or
// outside a vendor path, stays a syntax error.
func TestAddDeclaration(t *testing.T) {
	express := readFixture(t, fixtureNamed(t, "express_vulnerable"))
	tests := []struct {
		name        string
		path, src   string
		declaration bool // AddDeclaration, else AddJavaScript
		wantIgnored Ignored
		wantRoutes  bool
		wantSyntax  bool
	}{
		{"broken vendor declaration", "node_modules/router/lib/route.d.ts", routerDeclaration, true, IgnoredVendor, false, false},
		{"same through AddJavaScript", "node_modules/router/lib/route.d.ts", routerDeclaration, false, 0, false, true},
		{"broken first-party declaration", "types/route.d.ts", routerDeclaration, true, 0, false, true},
		{"route in a vendor declaration", "node_modules/app/app.d.ts", string(express), true, 0, true, false},
		{"block comment masked", "node_modules/router/a.d.ts", "/* express */\n" + routerDeclaration, true, IgnoredVendor, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := testParser(t).Parse(context.Background(), TypeScript, []byte(tt.src))
			if err != nil {
				t.Fatal(err)
			}
			if tt.src == routerDeclaration && !tree.HasError {
				t.Fatal("the grammar parses the router declaration now; pick a snippet it cannot")
			}
			e := NewExtractor()
			add := e.AddJavaScript
			if tt.declaration {
				add = e.AddDeclaration
			}
			if err := add(tt.path, tree, []byte(tt.src)); err != nil {
				t.Fatal(err)
			}
			g := e.Graph()
			f := g.Files[0]
			if f.Ignored != tt.wantIgnored || (len(g.Routes) > 0) != tt.wantRoutes || f.SyntaxError != tt.wantSyntax {
				t.Errorf("file %+v with %d routes; want ignored %v, routes %v, syntax error %v", f, len(g.Routes), tt.wantIgnored, tt.wantRoutes, tt.wantSyntax)
			}
		})
	}
}

// TestAddDeclarationFailsClosed (#262): a broken vendor declaration whose
// code, comments aside, might hold a route is never vendor. It is a syntax
// error, and a route the extractor still finds is evaluated.
func TestAddDeclarationFailsClosed(t *testing.T) {
	for name, src := range brokenRouteCode {
		t.Run(name, func(t *testing.T) {
			tree, err := testParser(t).Parse(context.Background(), TypeScript, []byte(src))
			if err != nil {
				t.Fatal(err)
			}
			if !tree.HasError {
				t.Fatal("the case parses cleanly, so it proves nothing")
			}
			e := NewExtractor()
			if err := e.AddDeclaration("node_modules/router/lib/route.d.ts", tree, []byte(src)); err != nil {
				t.Fatal(err)
			}
			if f := e.Graph().Files[0]; f.Ignored != 0 || !f.SyntaxError {
				t.Errorf("file %+v; want a syntax error, not ignored", f)
			}
		})
	}
}

func TestAddDeclarationRefuses(t *testing.T) {
	ts, err := testParser(t).Parse(context.Background(), TypeScript, []byte("export {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	py, err := testParser(t).Parse(context.Background(), Python, []byte("x = 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := NewExtractor()
	if err := e.AddDeclaration("node_modules/a/index.ts", ts, []byte("export {}\n")); err == nil {
		t.Error("a non-declaration file was accepted")
	}
	if err := e.AddDeclaration("node_modules/a/index.d.ts", py, []byte("x = 1\n")); err == nil {
		t.Error("a Python tree was accepted")
	}
	if len(e.Graph().Files) != 0 {
		t.Errorf("refused files were listed: %+v", e.Graph().Files)
	}
}
