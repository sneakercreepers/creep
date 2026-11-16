package static

import (
	"strconv"
	"strings"
	"testing"
)

// jsStackCases pin the review findings on #201: every middleware and
// handler of a route is scanned, unresolvable entries mark the route
// partial, receivers resolve by scope, every mount is kept with its own
// auth, and auth hints see through casts and ambiguous use() paths.
var jsStackCases = []struct {
	name, file, src, want string
}{
	{"inline middleware sink is scanned", "app.js", jsHeader + `function h(req, res) { res.send("ok"); }
app.get("/x", (req, res, next) => { cp.exec(req.query.c); next(); }, h);
`, `GET /x express auth=none params=0 dynamic=false handler=h:4
  shell child_process.exec line=5 dynamic=true parameterized=false indirect=false
`},
	{"same-file middleware sink is scanned", "app.js", jsHeader + `function loadUser(req, res, next) { db.query("SELECT * FROM u WHERE id = " + req.params.id); next(); }
function h(req, res) { res.send("ok"); }
app.get("/y/:id", loadUser, h);
`, `GET /y/:id express auth=none params=1 dynamic=false handler=h:5
  sql .query line=4 dynamic=true parameterized=false indirect=false
`},
	{"auth after the handler does not guard it", "app.js", jsHeader + `function h(req, res) { cp.exec(req.query.c); }
app.get("/z", h, requireAuth);
`, `GET /z express auth=none params=0 dynamic=false handler=h:4
  shell child_process.exec line=4 dynamic=true parameterized=false indirect=false
`},
	{"unresolvable middleware marks the route partial", "app.js", jsHeader + `app.post("/u", upload.single("f"), (req, res) => {});
app.get("/g", passport.authenticate("jwt"), (req, res) => {});
`, `file 0 syntax_error=false truncated=true
POST /u express auth=none params=0 dynamic=false handler=:4 partial=true
GET /g express auth=middleware params=0 dynamic=false handler=:5
`},
	{"same-file factory and wrapper are scanned", "app.js", jsHeader + `function guard(role) { return (req, res, next) => { db.query(role); next(); }; }
const wrap = (fn) => (req, res) => fn(req, res);
app.get("/f", guard(ROLE), wrap((req, res) => { cp.exec(req.query.c); }));
`, `GET /f express auth=none params=0 dynamic=false handler=:6
  sql .query line=4 dynamic=true parameterized=false indirect=false
  shell child_process.exec line=6 dynamic=true parameterized=false indirect=false
`},
	{"routers sharing a name in two functions keep their own auth", "app.js", `const express = require("express");
function adminRoutes() { const router = express.Router(); router.use(requireAdmin); router.get("/a", (req, res) => {}); return router; }
function publicRoutes() { const router = express.Router(); router.get("/b", (req, res) => { require("child_process").exec(req.query.c); }); return router; }
`, `GET /a express auth=middleware params=0 dynamic=false handler=:2
GET /b express auth=none params=0 dynamic=false handler=:3
  shell child_process.exec line=3 dynamic=true parameterized=false indirect=false
`},
	{"a reassigned app claims no auth", "app.js", `const express = require("express");
let app = express();
app.use(requireAuth);
app = express();
app.get("/x", (req, res) => {});
`, `GET /x express auth=none params=0 dynamic=false handler=:5
`},
	{"a parameter shadows an outer router", "app.js", `const express = require("express");
const router = express.Router();
router.use(requireAuth);
function mount(router) { router.get("/p", (req, res) => {}); }
`, `GET /p express auth=none params=0 dynamic=false handler=:4
`},
	{"a router mounted twice keeps both mounts", "app.js", jsHeader + `const r = express.Router();
r.get("/x", (req, res) => { db.query(req.query.q); });
app.use("/priv", requireLogin, r);
app.use("/pub", r);
`, `GET /priv/x express auth=middleware params=0 dynamic=false handler=:5
  sql .query line=5 dynamic=true parameterized=false indirect=false
GET /pub/x express auth=none params=0 dynamic=false handler=:5
  sql .query line=5 dynamic=true parameterized=false indirect=false
`},
	{"connect-ensure-login names are auth", "app.js", jsHeader + `app.get("/e", ensureLoggedIn(), (req, res) => {});
app.get("/i", isLoggedIn, (req, res) => {});
`, `GET /e express auth=middleware params=0 dynamic=false handler=:4
GET /i express auth=middleware params=0 dynamic=false handler=:5
`},
	{"typescript casts are seen through", "app.ts", `import express, { RequestHandler } from "express";
import * as cp from "child_process";
const app = express() as express.Express;
app.use(requireAuth as RequestHandler);
app.get("/t", <RequestHandler>checkRole, ((req, res) => { cp.exec("ls" as string); }) as RequestHandler);
`, `GET /t express auth=middleware params=0 dynamic=false handler=:5
  shell child_process.exec line=5 dynamic=false parameterized=false indirect=false
`},
	{"use(call(), auth) may be path-scoped", "app.js", jsHeader + `app.use(prefix(), requireAuth);
app.get("/x", (req, res) => {});
app.use(express.json(), requireAuth);
app.get("/y", (req, res) => {});
`, `GET /x express auth=none params=0 dynamic=false handler=:5
GET /y express auth=middleware params=0 dynamic=false handler=:7
`},
	{"auth after a router in one use() guards later routes only", "app.js", jsHeader + `const r = express.Router();
r.get("/a", (req, res) => {});
app.use("/x", r, requireAuth);
app.get("/x/b", (req, res) => {});
`, `GET /x/a express auth=none params=0 dynamic=false handler=:5
GET /x/b express auth=middleware params=0 dynamic=false handler=:7
`},
}

func TestJSRouteStacks(t *testing.T) {
	for _, c := range jsStackCases {
		t.Run(c.name, func(t *testing.T) {
			if got := summarize(extractFile(t, c.file, []byte(c.src))); got != c.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, c.want)
			}
		})
	}
}

// TestJSMountFanOutIsCapped: a router mounted more often than the cap
// expands to maxMountPaths routes, and the route is marked partial, since a
// dropped mount may be public.
func TestJSMountFanOutIsCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString(jsHeader + "const r = express.Router();\nr.get('/x', (req, res) => {});\n")
	for i := range maxMountPaths + 4 {
		b.WriteString("app.use('/m" + strconv.Itoa(i) + "', r);\n")
	}
	g, l := extractWith(t, defaultLimits(), b.String())
	if len(g.Routes) != maxMountPaths || !g.Routes[0].Partial || !g.Files[0].Truncated {
		t.Errorf("routes %d:\n%s", len(g.Routes), summarize(g, l))
	}
}

// TestJSStackEntriesAreCapped: a route with more entries than the cap is
// partial, never silently trimmed.
func TestJSStackEntriesAreCapped(t *testing.T) {
	src := jsHeader + "function m(req, res, next) { next(); }\napp.get('/x', " + strings.Repeat("m,\n", maxStackEntries+1) + "(req, res) => {});\n"
	g, l := extractWith(t, defaultLimits(), src)
	if len(g.Routes) != 1 || !g.Routes[0].Partial {
		t.Errorf("%s", summarize(g, l))
	}
}

// TestJSNameBindingsAreCapped: past maxNameBindings a receiver name
// resolves to nothing, so it claims no auth.
func TestJSNameBindingsAreCapped(t *testing.T) {
	src := "const express = require('express');\n" +
		strings.Repeat("function f() { const app = express(); }\n", maxNameBindings) +
		"function g() { const app = express(); app.use(requireAuth); app.get('/x', (req, res) => {}); }\n"
	g, l := extractWith(t, defaultLimits(), src)
	if len(g.Routes) != 1 || g.Routes[0].Auth != 0 {
		t.Errorf("%s", summarize(g, l))
	}
}
