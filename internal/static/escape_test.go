package static

import (
	"strings"
	"testing"
	"time"
)

const (
	escapeJSHead = "const express = require(\"express\")\nconst app = express()\nconst h = (req, res) => res.send(req.query.x)\n"
	escapePyHead = "import builtins, operator, subprocess\nfrom flask import Flask, request\nfrom flask_cors import CORS\napp = Flask(__name__)\n"
	escapePyDef  = "def run():\n    return request.args['x']\n"
)

// notReadAsClean reports whether static either evaluated the /run route or
// marked the file or a route not evaluated in full.
func notReadAsClean(g Graph, l Locations) bool {
	if len(g.Files) > 0 && (g.Files[0].Truncated || g.Files[0].SyntaxError) {
		return true
	}
	for _, r := range g.Routes {
		if r.Partial || l.Routes[r.ID].Path == "/run" {
			return true
		}
	}
	return false
}

// TestReceiverEscapes (#255 tester M5 and L4, maintainer decision): every
// spelling that reaches a known app or router, or a module imported
// dynamically, outside the forms static reads is evaluated or marks the
// file not evaluated in full. None reads as clean.
func TestReceiverEscapes(t *testing.T) {
	js := map[string]string{ //nolint:gosec // G101: case names such as "passed", no credentials
		"parenthesized callee":    `(app.get)("/run", h)`,
		"comma callee":            `(0, app.get)("/run", h)`,
		"call":                    `app.get.call(app, "/run", h)`,
		"apply":                   `app.get.apply(app, ["/run", h])`,
		"bind":                    "const g = app.get.bind(app)\ng(\"/run\", h)",
		"bound subscript":         `app["get"].bind(app)("/run", h)`,
		"destructured":            "const { get } = app\nget.call(app, \"/run\", h)",
		"reflect get":             `Reflect.get(app, "get").call(app, "/run", h)`,
		"reflect apply":           `Reflect.apply(app.get, app, ["/run", h])`,
		"held in an object":       "const o = { a: app }\no[\"a\"][\"get\"](\"/run\", h)",
		"held in an array":        "const a = [app]\na[0].get(\"/run\", h)",
		"passed to a function":    "function reg(x) { x.get(\"/run\", h) }\nreg(app)",
		"aliased":                 "const a2 = app\na2.get(\"/run\", h)",
		"chained off a call":      `app.use(h).get("/run", h)`,
		"router member read":      `app.router.get("/run", h)`,
		"spread":                  `reg(...[app])`,
		"stored on an object key": `globalThis.server = app`,
	}
	for name, code := range js {
		t.Run("js "+name, func(t *testing.T) {
			if !notReadAsClean(extractFile(t, "app.js", []byte(escapeJSHead+code+"\n"))) {
				t.Error("the route reads as clean")
			}
		})
	}
	py := map[string]string{
		"parenthesized decorator": "@(app.route(\"/run\"))\n" + escapePyDef,
		"parenthesized attribute": "@(app.route)(\"/run\")\n" + escapePyDef,
		"builtins.getattr":        "@builtins.getattr(app, \"route\")(\"/run\")\n" + escapePyDef,
		"aliased getattr":         "ga = getattr\n\n@ga(app, \"route\")(\"/run\")\n" + escapePyDef,
		"attrgetter":              "@operator.attrgetter(\"route\")(app)(\"/run\")\n" + escapePyDef,
		"vars":                    "@vars(app)[\"route\"](\"/run\")\n" + escapePyDef,
		"passed to a function":    "def reg(a):\n    a.add_url_rule('/run', view_func=run)\n\nreg(app)\n" + escapePyDef,
		"aliased app":             "a2 = app\n\n@a2.route(\"/run\")\n" + escapePyDef,
		"url_map":                 "app.url_map.add(None)\n" + escapePyDef,
		"local __import__":        "@app.get(\"/run\")\ndef run():\n    m = __import__(\"subprocess\")\n    m.call(request.args['c'], shell=True)\n    return 'x'\n",
		"builtins.__import__":     "@app.get(\"/run\")\ndef run():\n    builtins.__import__(\"os\").system(request.args['c'])\n    return 'x'\n",
		"getattr of __import__":   "@app.get(\"/run\")\ndef run():\n    getattr(__import__(\"os\"), \"system\")(request.args['c'])\n    return 'x'\n",
	}
	for name, code := range py {
		t.Run("py "+name, func(t *testing.T) {
			if !notReadAsClean(extractFile(t, "app.py", []byte(escapePyHead+code))) {
				t.Error("the route reads as clean")
			}
		})
	}
}

// TestBenignReceiverUses: the allowlist of uses that reach no route keeps
// an ordinary app complete, so the rule does not make every project
// incomplete.
func TestBenignReceiverUses(t *testing.T) {
	js := map[string]string{
		"listen":              `const server = app.listen(3000)`,
		"locals":              `app.locals.title = "x"`,
		"settings":            `if (app.settings.env) {}`,
		"mount":               "const r = express.Router()\nr.get(\"/x\", h)\napp.use(\"/a\", r)",
		"route chain":         `app.route("/y").get(h).post(h)`,
		"module.exports":      `module.exports = app`,
		"exports object":      `module.exports = { app, h }`,
		"exports property":    `exports.app = app`,
		"export default":      `export default app`,
		"named createServer":  "const http = require(\"http\")\nhttp.createServer(app).listen(1)",
		"factory return":      "function make() { const a = express(); a.get(\"/x\", h); return a }",
		"subscript with call": `app["post"]("/y", h)`,
	}
	for name, code := range js {
		t.Run("js "+name, func(t *testing.T) {
			g, _ := extractFile(t, "app.js", []byte(escapeJSHead+"app.get(\"/run\", h)\n"+code+"\n"))
			if f := g.Files[0]; f.Truncated || f.SyntaxError {
				t.Errorf("file %+v is not complete", f)
			}
		})
	}
	py := map[string]string{
		"config":          "app.config['SECRET_KEY'] = 'x'\napp.secret_key = 'y'",
		"run":             "if __name__ == '__main__':\n    app.run(debug=app.debug)",
		"cors":            "CORS(app)",
		"uvicorn":         "import uvicorn\nuvicorn.run(app, port=1)",
		"blueprint mount": "from flask import Blueprint\nbp = Blueprint('b', __name__)\napp.register_blueprint(bp, url_prefix='/b')",
		"bare decorator":  "@app.teardown_appcontext\ndef close(_):\n    pass",
		"factory":         "def create_app():\n    app = Flask(__name__)\n    return app",
		"getattr literal": "@getattr(app, 'post')('/y')\ndef y():\n    return 'y'",
		"module import":   "os_ = __import__('os')",
		"inline import":   "def f():\n    __import__('os').getcwd()",
	}
	for name, code := range py {
		t.Run("py "+name, func(t *testing.T) {
			src := escapePyHead + "\n@app.get(\"/run\")\n" + escapePyDef + "\n" + code + "\n"
			g, _ := extractFile(t, "app.py", []byte(src))
			if f := g.Files[0]; f.Truncated || f.SyntaxError {
				t.Errorf("file %+v is not complete", f)
			}
		})
	}
}

// TestLibraryDynamicImportStaysComplete: a dynamic import counts only in a
// file with routes, so library code that loads plugins (flask/cli.py)
// stays complete, while a hidden receiver use counts everywhere.
func TestLibraryDynamicImportStaysComplete(t *testing.T) {
	lib := "import importlib\n\ndef load(name):\n    return importlib.import_module(name).main()\n"
	if g, _ := extractFile(t, "lib.py", []byte(lib)); g.Files[0].Truncated {
		t.Errorf("library file %+v is not complete", g.Files[0])
	}
	hidden := escapePyHead + "@builtins.getattr(app, \"route\")(\"/run\")\n" + escapePyDef
	if g, _ := extractFile(t, "lib.py", []byte(hidden)); !g.Files[0].Truncated {
		t.Errorf("a file whose only route is hidden is complete: %+v", g.Files[0])
	}
}

// TestReceiverEscapesIsLinear: the check visits each node once.
func TestReceiverEscapesIsLinear(t *testing.T) {
	src := escapeJSHead + strings.Repeat("app.locals.x = app.settings.y\n", 20000)
	start := time.Now()
	g, _ := extractFile(t, "app.js", []byte(src))
	if d := time.Since(start); d > 30*time.Second || g.Files[0].Truncated {
		t.Errorf("%v, file %+v", d, g.Files[0])
	}
}
