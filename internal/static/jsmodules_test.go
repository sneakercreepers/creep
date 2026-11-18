package static

import "testing"

const esmHeader = "import express from 'express';\nconst app = express();\n"

// jsModuleCases pin cycle 2 of the #201 review. (A) A receiver imported
// from a module of the repository (a model, a db client) is matched by
// method name like any variable, and a call into such a module that is no
// sink makes the route partial, never silently empty; packages do not fall
// back, so ReactDOM.render stays out. (B) A router that escapes (an alias,
// a helper argument, an export) and is mounted in the file claims no auth
// from its mounts and is partial.
var jsModuleCases = []struct {
	name, file, src, want string
}{
	{"require default model", "app.js", jsHeader + `const User = require("./models/User");
app.post("/login", async (req, res) => { await User.findOne({ username: req.body.username }); });
`, `POST /login express auth=none params=0 dynamic=false handler=:5
  nosql .findOne line=5 dynamic=true parameterized=false indirect=false
`},
	{"require default db client", "app.js", jsHeader + `const db = require("./db");
app.get("/a", (req, res) => { db.query("SELECT * FROM t WHERE id=" + req.query.id); });
`, `GET /a express auth=none params=0 dynamic=false handler=:5
  sql .query line=5 dynamic=true parameterized=false indirect=false
`},
	{"require destructured and aliased", "app.js", jsHeader + `const { sequelize } = require("./db");
const { pool: pg } = require("../lib/db.js");
app.get("/b", (req, res) => { sequelize.query("SELECT " + req.query.q); pg.query("SELECT 1", [req.query.q]); });
`, `GET /b express auth=none params=0 dynamic=false handler=:6
  sql .query line=6 dynamic=true parameterized=false indirect=false
  sql .query line=6 dynamic=false parameterized=true indirect=false
`},
	{"direct require call", "app.js", jsHeader + `app.get("/c", (req, res) => { require("./db").query(req.query.q); });
`, `GET /c express auth=none params=0 dynamic=false handler=:4
  sql .query line=4 dynamic=true parameterized=false indirect=false
`},
	{"esm default, named and namespace imports", "app.mjs", esmHeader + `import db from "./db.js";
import { User } from "./models/index.js";
import * as repo from "../repo";
app.get("/d", async (req, res) => {
  await db.query(req.query.q);
  await User.find(req.query);
  await repo.users.findOne({ id: req.params.id });
});
`, `GET /d express auth=none params=0 dynamic=false handler=:6
  sql .query line=7 dynamic=true parameterized=false indirect=false
  nosql .find line=8 dynamic=true parameterized=false indirect=false
  nosql .findOne line=9 dynamic=true parameterized=false indirect=false
`},
	{"typescript path alias import", "app.ts", esmHeader + `import { Item } from "@/models/item";
app.delete("/e", async (req, res) => { await Item.deleteMany(req.body); });
`, `DELETE /e express auth=none params=0 dynamic=false handler=:4
  nosql .deleteMany line=4 dynamic=true parameterized=false indirect=false
`},
	{"unclassifiable local calls make the route partial", "app.js", jsHeader + `const svc = require("./svc");
const { getUser } = require("./users");
const items = require("./items");
app.post("/f", (req, res) => { svc.createUser(req.body); });
app.get("/g", (req, res) => { getUser(req.query.id); });
app.get("/h", (req, res) => { items.find((i) => i.id === req.query.id); });
`, `file 0 syntax_error=false truncated=true
POST /f express auth=none params=0 dynamic=false handler=:7 partial=true
GET /g express auth=none params=0 dynamic=false handler=:8 partial=true
GET /h express auth=none params=0 dynamic=false handler=:9 partial=true
`},
	{"packages never fall back to method names", "app.js", jsHeader + `const ReactDOM = require("react-dom");
const _ = require("lodash");
app.get("/i", (req, res) => { ReactDOM.render(req.query.v); _.find(req.query.list, req.query.k); });
`, `GET /i express auth=none params=0 dynamic=false handler=:6
`},
	{"router mounted through an alias claims no mount auth", "app.js", jsHeader + `const r = express.Router();
r.get("/x", (req, res) => {});
const pub = r;
app.use("/priv", requireLogin, r);
app.use("/pub", pub);
`, `file 0 syntax_error=false truncated=true
GET /priv/x express auth=none params=0 dynamic=false handler=:5 partial=true
`},
	{"router mounted through a helper parameter claims no mount auth", "app.js", jsHeader + `const r = express.Router();
r.get("/x", (req, res) => {});
function addPublic(a, router) { a.use("/pub", router); }
app.use("/priv", requireLogin, r);
addPublic(app, r);
`, `file 0 syntax_error=false truncated=true
GET /priv/x express auth=none params=0 dynamic=false handler=:5 partial=true
`},
	{"an escaped router keeps its own use() auth", "app.js", jsHeader + `const r = express.Router();
r.use(requireAuth);
r.get("/x", (req, res) => {});
app.use("/a", r);
module.exports = r;
`, `file 0 syntax_error=false truncated=true
GET /a/x express auth=middleware params=0 dynamic=false handler=:6 partial=true
`},
	{"an exported router or app that is not mounted in the file is complete", "app.js", jsHeader + `const r = express.Router();
r.use(requireAuth);
r.get("/x", (req, res) => {});
app.use("/a", r);
module.exports = { app };
`, `GET /a/x express auth=middleware params=0 dynamic=false handler=:6
`},
}

func TestJSLocalModulesAndEscapes(t *testing.T) {
	for _, c := range jsModuleCases {
		t.Run(c.name, func(t *testing.T) {
			if got := summarize(extractFile(t, c.file, []byte(c.src))); got != c.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, c.want)
			}
		})
	}
}

func TestLocalModule(t *testing.T) {
	for spec, want := range map[string]bool{
		"./db": true, "../models/User": true, ".": true, "/srv/app/db": true, "@/models": true, "~/lib/db": true, "#models/item": true,
		"express": false, "@prisma/client": false, "node-fetch": false, "fs.promises": false, "src/db": false, "@app/models": false, "": false,
	} {
		if localModule(spec) != want {
			t.Errorf("%q: want %v", spec, want)
		}
	}
}
