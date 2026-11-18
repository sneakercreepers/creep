package static

import "testing"

// jsAliasCases pin #210. N1: a "#" subpath import is a module of the
// repository; a sink-named method on any other import that is neither
// relative nor a known package (a tsconfig paths alias such as src/db or
// @app/models) marks the route partial, never an empty complete route.
// N2: ".find" on an unknown receiver is a sink when its filter is an object
// literal, comes from req, or the receiver is an in-file model or
// collection; a callback or literal is no sink; anything else is partial.
var jsAliasCases = []struct {
	name, file, src, want string
}{
	{"subpath imports are local", "app.mjs", esmHeader + `import { Item } from "#models/item";
const db = require("#db");
app.get("/a", async (req, res) => { await Item.find(req.query); await db.query(req.query.q); });
`, `GET /a express auth=none params=0 dynamic=false handler=:5
  nosql .find line=5 dynamic=true parameterized=false indirect=false
  sql .query line=5 dynamic=true parameterized=false indirect=false
`},
	{"sink-named calls on unresolved aliases are partial", "app.ts", esmHeader + `import db from "src/db";
import { User, Item } from "@app/models";
import { query } from "lib/sql";
app.get("/a", (req, res) => { db.query(req.query.q); });
app.post("/b", async (req, res) => { await User.findOne(req.body); });
app.get("/c", async (req, res) => { await Item.find(req.query); });
app.get("/d", (req, res) => { query("SELECT " + req.query.q); });
`, `file 0 syntax_error=false truncated=true
GET /a express auth=none params=0 dynamic=false handler=:6 partial=true
POST /b express auth=none params=0 dynamic=false handler=:7 partial=true
GET /c express auth=none params=0 dynamic=false handler=:8 partial=true
GET /d express auth=none params=0 dynamic=false handler=:9 partial=true
`},
	{"known packages and other methods stay complete", "app.js", jsHeader + `const ReactDOM = require("react-dom/server");
const find = require("lodash/find");
const nunjucks = require("nunjucks");
const cfg = require("src/config");
const R = require("ramda");
const { execute } = require("graphql");
const { query } = require("express-validator");
app.get("/a", (req, res) => { ReactDOM.render(req.query.v); find(req.query.l, req.query.k); nunjucks.render("t.html"); cfg.get(req.query.k); });
app.get("/b", (req, res) => { R.find(R.propEq(req.query.k), list); execute({ schema, document: req.body }); query("id"); });
`, `GET /a express auth=none params=0 dynamic=false handler=:11
GET /b express auth=none params=0 dynamic=false handler=:12
`},
	{"unlisted database packages stay partial", "app.js", jsHeader + `const knex = require("knex")({ client: "pg" });
const { sql } = require("@vercel/postgres");
const db = require("knex");
app.get("/a", (req, res) => { db.raw("SELECT " + req.query.q); });
app.get("/b", (req, res) => { sql.query("SELECT " + req.query.q); });
`, `file 0 syntax_error=false truncated=true
GET /a express auth=none params=0 dynamic=false handler=:7 partial=true
GET /b express auth=none params=0 dynamic=false handler=:8 partial=true
`},
	{"in-file mongoose model and native collection find", "app.js", jsHeader + `const mongoose = require("mongoose");
const User = mongoose.model("User", new mongoose.Schema({}));
app.get("/a", async (req, res) => { await User.find(req.query); });
app.get("/b", async (req, res) => { await req.app.locals.db.collection("users").find(req.body); });
app.get("/c", async (req, res) => { const f = req.query; const g = f; await User.find(g); });
app.get("/d", async (req, res) => { const users = db.collection("users"); await users.find(buildFilter(req)); });
`, `GET /a express auth=none params=0 dynamic=false handler=:6
  nosql .find line=6 dynamic=true parameterized=false indirect=false
GET /b express auth=none params=0 dynamic=false handler=:7
  nosql .find line=7 dynamic=true parameterized=false indirect=false
GET /c express auth=none params=0 dynamic=false handler=:8
  nosql .find line=8 dynamic=true parameterized=false indirect=false
GET /d express auth=none params=0 dynamic=false handler=:9
  nosql .find line=9 dynamic=true parameterized=false indirect=false
`},
	{"find on an unknown receiver", "app.js", jsHeader + `app.get("/a", (req, res) => { Items.find(req.query); });
app.get("/b", (req, res) => { const q = req.body.filter; Items.find(q); });
app.get("/c", (req, res) => { arr.find(isAdmin); });
app.get("/d", (req, res) => { arr.find((x) => x.id === req.query.id); arr.find("x"); arr.find(); });
app.get("/e", (req, res) => { Items.find(someVar); });
app.get("/f", (req, res) => { const a = req.query; const b = a; const c = b; const d = c; Items.find(d); });
app.get("/g", (req, res) => { const a = req.query; const b = a; const c = b; const d = c; const e = d; Items.find(e); });
`, `file 0 syntax_error=false truncated=true
GET /a express auth=none params=0 dynamic=false handler=:4
  nosql .find line=4 dynamic=true parameterized=false indirect=false
GET /b express auth=none params=0 dynamic=false handler=:5
  nosql .find line=5 dynamic=true parameterized=false indirect=false
GET /c express auth=none params=0 dynamic=false handler=:6 partial=true
GET /d express auth=none params=0 dynamic=false handler=:7
GET /e express auth=none params=0 dynamic=false handler=:8 partial=true
GET /f express auth=none params=0 dynamic=false handler=:9
  nosql .find line=9 dynamic=true parameterized=false indirect=false
GET /g express auth=none params=0 dynamic=false handler=:10 partial=true
`},
}

func TestJSAliasesAndFind(t *testing.T) {
	for _, c := range jsAliasCases {
		t.Run(c.name, func(t *testing.T) {
			if got := summarize(extractFile(t, c.file, []byte(c.src))); got != c.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, c.want)
			}
		})
	}
}

func TestPackageRootAndMember(t *testing.T) {
	cases := []struct{ spec, root, member string }{
		{"lodash", "lodash", ""},
		{"lodash/find", "lodash", ""},
		{"@app/models.User", "@app/models", "User"},
		{"@prisma/client/runtime", "@prisma/client", ""},
		{"src/db.query", "src", "query"},
		{"child_process.exec", "child_process", "exec"},
		{"socket.io", "socket", "io"},
	}
	for _, c := range cases {
		if got := packageRoot(c.spec); got != c.root {
			t.Errorf("packageRoot(%q) = %q, want %q", c.spec, got, c.root)
		}
		if got := namedMember(c.spec); got != c.member {
			t.Errorf("namedMember(%q) = %q, want %q", c.spec, got, c.member)
		}
	}
}
