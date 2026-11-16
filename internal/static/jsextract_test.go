package static

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

var jsExtractCases = []struct {
	name, file, src, want string
}{
	{"require styles and per-route middleware", "app.js", `const express = require("express");
const { exec: run } = require("child_process");
const cp = require("node:child_process");
const fs = require("fs").promises;
const app = express();
app.get("/a/:id", requireLogin, (req, res) => {
  run(req.query.c);
  cp.execSync("ls");
  fs.readFile(req.params.id);
});
`, `GET /a/:id express auth=middleware params=1 dynamic=false handler=:6
  shell child_process.exec line=7 dynamic=true parameterized=false indirect=false
  shell child_process.execSync line=8 dynamic=false parameterized=false indirect=false
  file fs.readFile line=9 dynamic=true parameterized=false indirect=false
`},
	{"app.use guards only later routes", "app.js", `const express = require("express");
const app = express();
app.get("/before", (req, res) => {});
app.use(express.json());
app.use(authenticate);
app.get("/after", (req, res) => {});
`, `GET /before express auth=none params=0 dynamic=false handler=:3
GET /after express auth=middleware params=0 dynamic=false handler=:6
`},
	{"mounts compose prefixes and auth", "app.mjs", `import express, { Router } from "express";
const app = express();
const api = express.Router();
const v1 = Router();
const open = Router();
const admin = Router();
v1.post("/items/:id", (req, res) => {
  db.query(` + "`DELETE FROM t WHERE id = ${req.params.id}`" + `);
});
open.get("/x", (req, res) => {});
admin.get("/stats", (req, res) => {});
api.use("/v1/", v1);
app.use("/open", rateLimit, open);
app.use(jwtCheck);
app.use("/api", api);
app.use("/admin", [requireAdmin], admin);
`, `POST /api/v1/items/:id express auth=middleware params=1 dynamic=false handler=:7
  sql .query line=8 dynamic=true parameterized=false indirect=false
GET /open/x express auth=none params=0 dynamic=false handler=:10
GET /admin/stats express auth=middleware params=0 dynamic=false handler=:11
`},
	{"route chain with all() auth", "app.js", `const express = require("express");
const router = express.Router();
router.route("/u/:id").all(isAuthenticated).get((req, res) => {}).put((req, res) => {});
router.route("/v").get((req, res) => {});
`, `PUT /u/:id express auth=middleware params=1 dynamic=false handler=:3
GET /u/:id express auth=middleware params=1 dynamic=false handler=:3
GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|OTHER /u/:id express auth=none params=1 dynamic=false handler=isAuthenticated:3
GET /v express auth=none params=0 dynamic=false handler=:4
`},
	{"path-scoped guards respect segments", "app.js", `const app = require("express")();
app.all("/admin/*", requireAdmin);
app.use("/reports/", checkToken);
app.get("/admin/users", (req, res) => {});
app.get("/administrator", (req, res) => {});
app.get("/reports", (req, res) => {});
app.get("/reportsx", (req, res) => {});
app.use(PREFIX + "/x", requireAdmin);
app.get("/y", (req, res) => {});
`, `GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|OTHER /admin/* express auth=none params=1 dynamic=false handler=requireAdmin:2
GET /admin/users express auth=middleware params=0 dynamic=false handler=:4
GET /administrator express auth=none params=0 dynamic=false handler=:5
GET /reports express auth=middleware params=0 dynamic=false handler=:6
GET /reportsx express auth=none params=0 dynamic=false handler=:7
GET /y express auth=none params=0 dynamic=false handler=:9
`},
	{"dynamic paths and prefixes", "app.js", `const express = require("express");
const app = express();
const r = express.Router();
app.get(PATH, (req, res) => {});
app.get(/^\/re/, (req, res) => {});
app.get("/t/" + "x", (req, res) => {});
app.get(` + "`/t/${v}`" + `, (req, res) => {});
r.get("/y", (req, res) => {});
app.use(API_PREFIX, r);
`, `GET  express auth=none params=0 dynamic=true handler=:4
GET  express auth=none params=0 dynamic=true handler=:5
GET /t/x express auth=none params=0 dynamic=false handler=:6
GET  express auth=none params=0 dynamic=true handler=:7
GET  express auth=none params=0 dynamic=true handler=:8
`},
	{"unknown receivers need express and a local handler", "routes.js", `const express = require("express");
const axios = require("axios");
module.exports = (router) => {
  router.get("/p", (req, res) => { axios.get(req.query.u); });
  axios.get("/x", () => {});
  cache.get("/k", other.fn);
  store.get(key, () => {});
  store.get("k", () => {});
};
`, `GET /p express auth=none params=0 dynamic=false handler=:4
  http_client axios.get line=4 dynamic=true parameterized=false indirect=false
`},
	{"no express import, no guessed routes", "lib.js", `thing.get("/x", (req, res) => { fetch(req.query.u); });
`, ``},
	{"named, wrapped and imported handlers", "app.js", `const express = require("express");
const ctrl = require("./ctrl");
const cp = require("child_process");
const app = express();
async function list(req, res) {
  const q = "SELECT 1";
  await db.query(q);
}
const show = async (req, res) => { helper(req.params.id); helper(1); };
function helper(id) {
  cp.spawn(id);
}
app.get("/list", list);
app.get("/show/:id", catchAsync(show));
app.get("/ctrl", ctrl.index);
`, `file 0 syntax_error=false truncated=true
GET /list express auth=none params=0 dynamic=false handler=list:5
  sql .query line=7 dynamic=false parameterized=false indirect=false
GET /show/:id express auth=none params=1 dynamic=false handler=show:9 partial=true
  shell child_process.spawn line=11 dynamic=true parameterized=false indirect=true
GET /ctrl express auth=none params=0 dynamic=false handler=ctrl.index:15 partial=true
`},
	{"tagged templates and Array.find are not sinks", "app.js", `const express = require("express");
const app = express();
app.get("/t", (req, res) => {
  sql` + "`SELECT ${req.query.a}`" + `;
  String.raw` + "`x`" + `;
  items.find((i) => i.id === req.query.id);
  Users.find({ name: req.query.n });
  db.query("SELECT * FROM t WHERE a = ?", [req.query.a]);
  db.query(req.query.q, (err, rows) => {});
});
`, `GET /t express auth=none params=0 dynamic=false handler=:3
  nosql .find line=7 dynamic=true parameterized=false indirect=false
  sql .query line=8 dynamic=false parameterized=true indirect=false
  sql .query line=9 dynamic=true parameterized=false indirect=false
`},
	{"auth calls; require and .required() are not auth", "app.js", `const express = require("express");
const app = express();
app.get("/me", (req, res) => { const lib = require("lib"); Joi.string().required(); });
app.get("/me2", (req, res) => { verifyToken(req); });
`, `GET /me express auth=none params=0 dynamic=false handler=:3
GET /me2 express auth=call params=0 dynamic=false handler=:4
`},
	{"typescript import = require and typed handlers", "app.ts", `import express = require("express");
import { readFileSync as read } from "fs";
const app: express.Express = express();
app.get("/f/:name", (req: express.Request, res: express.Response): void => {
  const base: string = "/srv/";
  res.send(read(base + req.params.name));
});
`, `GET /f/:name express auth=none params=1 dynamic=false handler=:4
  file fs.readFileSync line=6 dynamic=true parameterized=false indirect=false
`},
	{"tsx parses with its own grammar", "app.tsx", `import express from "express";
const app = express();
app.post("/r", (req, res) => { res.render(req.body.view); });
`, `POST /r express auth=none params=0 dynamic=false handler=:3
  template .render line=3 dynamic=true parameterized=false indirect=false
`},
	{"syntax errors keep intact routes", "app.js", `const express = require("express");
const app = express();
const broken = [1, 2;
app.delete("/ok", (req, res) => { res.download(req.query.f); });
`, `file 0 syntax_error=true truncated=false
DELETE /ok express auth=none params=0 dynamic=false handler=:4
  file .download line=4 dynamic=true parameterized=false indirect=false
`},
	{"empty file", "app.js", ``, ``},
}

func TestExtractJavaScript(t *testing.T) {
	for _, c := range jsExtractCases {
		t.Run(c.name, func(t *testing.T) {
			if got := summarize(extractFile(t, c.file, []byte(c.src))); got != c.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, c.want)
			}
		})
	}
}

// TestSinkTablesKeepTheirIDs: the Python and JavaScript tables fit their
// SinkAPI ranges, so neither can grow into the other, and each name maps to
// one API.
func TestSinkTablesKeepTheirIDs(t *testing.T) {
	if len(pySinkSpecs) > int(jsSinkBase) || int(jsSinkBase)+len(jsSinkSpecs) > 256 {
		t.Fatalf("tables overflow: python %d, javascript %d from %d", len(pySinkSpecs), len(jsSinkSpecs), jsSinkBase)
	}
	seen := map[string]bool{}
	for i, s := range jsSinkSpecs {
		api, ok := lookupJSSink(strings.TrimPrefix(s.name, "."), strings.HasPrefix(s.name, "."))
		if seen[s.name] || !ok || api != jsSinkBase+SinkAPI(i) || api.Kind() != s.kind || s.kind == 0 {
			t.Errorf("%s: api %d ok %v", s.name, api, ok)
		}
		seen[s.name] = true
	}
	for _, alias := range []string{"fs/promises.readFile", "fs.promises.readFile", "fs-extra.readFile"} {
		if api, ok := lookupJSSink(alias, false); !ok || api.String() != "fs.readFile" {
			t.Errorf("%s: %s", alias, api)
		}
	}
	if _, ok := lookupJSSink("query", false); ok {
		t.Error("a method spec matched a plain function")
	}
}

func TestAddJavaScriptRejectsBadInput(t *testing.T) {
	p := testParser(t)
	src := []byte("const x = 1;\n")
	js, err := p.Parse(context.Background(), JavaScript, src)
	if err != nil {
		t.Fatal(err)
	}
	py, err := p.Parse(context.Background(), Python, []byte("x = 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		tree *Tree
		src  []byte
	}{
		{"nil tree", nil, src},
		{"no root", &Tree{Language: JavaScript}, src},
		{"not javascript", py, src},
		{"source shorter than tree", js, src[:2]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := NewExtractor()
			if err := e.AddJavaScript("a.js", c.tree, c.src); err == nil {
				t.Fatal("want error")
			}
			if len(e.Graph().Files) != 0 {
				t.Error("rejected file was added")
			}
		})
	}
}

// TestAddJavaScriptIgnoresVendorAndMinified: node_modules code and minified
// bundles with no route are listed as ignored, never extracted. A route in
// one, a .min.js name on hand-written code, or one padding line is
// extracted (pentest P4, #213).
func TestAddJavaScriptIgnoresVendorAndMinified(t *testing.T) {
	src := []byte("const app = require('express')();\napp.get('/x', (req, res) => { require('child_process').exec(req.query.c); });\n")
	lib := []byte("module.exports = function add(a, b) { return a + b; };\n")
	dense := func(code []byte) []byte {
		return []byte(strings.Repeat("/*"+strings.Repeat("x", 600)+"*/", 4) + string(code))
	}
	padded := []byte(strings.Repeat("x", 4000) + "\n" + strings.Repeat(string(src), 4))
	tests := []struct {
		name    string
		src     []byte
		ignored bool
	}{
		{"node_modules/pkg/index.js", lib, true},
		{"public/bundle.js", dense(lib), true},
		{"node_modules/pkg/server.js", src, false},
		{"public/app.js", dense(src), false},
		{"public/padded.js", padded, false},
		{"public/app.min.js", src, false},
	}
	for _, tt := range tests {
		e := NewExtractor()
		if err := addFile(t, e, tt.name, tt.src); err != nil {
			t.Fatal(err)
		}
		g := e.Graph()
		hasRoute := bytes.Contains(tt.src, []byte("app.get"))
		if len(g.Files) != 1 || (g.Files[0].Ignored != 0) != tt.ignored || (len(g.Routes) != 0) != hasRoute {
			t.Errorf("%s: files %+v routes %d", tt.name, g.Files, len(g.Routes))
		}
	}
}

// TestHostileTextStaysOutOfGraphJS plants an instruction in every place repo
// text can appear in an Express file; the serialized graph never carries it.
func TestHostileTextStaysOutOfGraphJS(t *testing.T) {
	const marker = "IGNOREPREVIOUSINSTRUCTIONS"
	src := `// ` + marker + `
const express = require("express");
const ` + marker + `app = express();
const ` + marker + `r = express.Router();
function ` + marker + `(req, res) {
  const ` + marker + `q = "` + marker + `";
  db.query(` + marker + `q);
}
` + marker + `r.get("/` + marker + `/:` + marker + `", require` + marker + `, ` + marker + `);
` + marker + `app.use("/` + marker + `", ` + marker + `r);
`
	e := NewExtractor()
	if err := addFile(t, e, marker+".js", []byte(src)); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(e.Graph())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(string(out)), marker) {
		t.Errorf("graph carries repository text: %s", out)
	}
	g, l := e.Graph(), e.Locations()
	if len(g.Routes) != 1 || len(g.Sinks) != 1 || g.Routes[0].Auth != AuthMiddleware || !strings.Contains(l.Routes[0].Path, marker) {
		t.Errorf("route lost: %s", summarize(g, l))
	}
}
