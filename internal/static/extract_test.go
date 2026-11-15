package static

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

var extractCases = []struct {
	name, src, want string
}{
	{"aliased imports", `import flask as fl
from requests import get as fetch
app = fl.Flask(__name__)
@app.route("/a", methods=["get", "Post"])
def a():
    return fetch(url)
`, `GET|POST /a flask auth=none params=0 dynamic=false handler=a:5
  http_client requests.get line=6 dynamic=true parameterized=false indirect=false
`},
	{"nested blueprints, mount prefix replaces own", `from flask import Flask, Blueprint
app = Flask(__name__)
api = Blueprint("api", __name__, url_prefix="/api")
v1 = Blueprint("v1", __name__, url_prefix="/ignored")
@v1.get("/<int:id>")
def item(id):
    return open("/data/x")
api.register_blueprint(v1, url_prefix="/v1")
app.register_blueprint(api)
`, `GET /api/v1/<int:id> flask auth=none params=1 dynamic=false handler=item:6
  file open line=7 dynamic=false parameterized=false indirect=false
`},
	{"nested routers carry dependencies", `from fastapi import FastAPI, APIRouter, Depends
app = FastAPI()
outer = APIRouter(prefix="/outer")
inner = APIRouter(prefix="/in")
@inner.delete("/{x}")
async def rm(x: int):
    subprocess.run(["rm", x])
outer.include_router(inner, prefix="/mid")
app.include_router(outer, dependencies=[Depends(verify_token)])
`, `DELETE /outer/mid/in/{x} fastapi auth=dependency params=1 dynamic=false handler=rm:6
`},
	{"dynamic path and methods", `from flask import Flask
app = Flask(__name__)
@app.route(PREFIX + "/x", methods=VERBS)
def x():
    pass
@app.route(f"/u/{name}", methods=["GET", "BREW", m])
def u():
    pass
`, `OTHER  flask auth=none params=0 dynamic=true handler=x:4
GET|OTHER  flask auth=none params=0 dynamic=true handler=u:7
`},
	{"dynamic blueprint prefix", `from flask import Flask, Blueprint
bp = Blueprint("b", __name__, url_prefix=cfg.prefix)
@bp.route("/x")
def x():
    pass
`, `GET  flask auth=none params=0 dynamic=true handler=x:4
`},
	{"syntax errors keep intact routes", `from flask import Flask
app = Flask(__name__)
def broken(:
    pass
@app.post("/ok")
def ok():
    os.system(cmd)
`, `file 0 syntax_error=true truncated=false
POST /ok flask auth=none params=0 dynamic=false handler=ok:6
`},
	{"receiver from another module", `from fastapi import Depends
from .app import router
@router.get("/r")
def r(user=Depends(get_current_user)):
    pass
@cache.route("/c")
def c():
    pass
`, `GET /r fastapi auth=dependency params=0 dynamic=false handler=r:4
GET /c flask auth=none params=0 dynamic=false handler=c:7
`},
	{"no framework import is not a route", `@cache.get("/k")
def k():
    pass
@app.route()
def none():
    pass
`, ``},
	{"mount cycle terminates", `from fastapi import APIRouter
a = APIRouter(prefix="/a")
b = APIRouter(prefix="/b")
a.include_router(b)
b.include_router(a)
@a.get("/x")
def x():
    pass
`, `GET  fastapi auth=none params=0 dynamic=true handler=x:7
`},
	{"auth decorator, Annotated and Security schemes", `from typing import Annotated
from fastapi import FastAPI, Depends, Security
from fastapi.security import HTTPBearer
from flask_login import login_required
app = FastAPI()
scheme = HTTPBearer()
@app.get("/a")
def a(c: Annotated[str, Depends(scheme)]):
    pass
@app.get("/b")
def b(u=Security(anything)):
    pass
@app.get("/c")
@login_required
def c(db=Depends(get_db)):
    pass
`, `GET /a fastapi auth=dependency params=0 dynamic=false handler=a:8
GET /b fastapi auth=dependency params=0 dynamic=false handler=b:11
GET /c fastapi auth=decorator params=0 dynamic=false handler=c:15
`},
	// q is also bound by `q += user`, so both sinks on q are dynamic: the
	// analysis is flow-insensitive and fails closed (#185).
	{"helpers, assignments and two routes on one handler", `from flask import Flask, render_template_string
app = Flask(__name__)
def run(sql):
    return db.execute(sql, (1,))
def nested_only():
    def inner():
        os.system(x)
@app.route("/a")
@app.route("/b")
def h():
    q = "SELECT 1"
    db.execute(q)
    q += user
    db.execute(q)
    run(x)
    run(y)
    nested_only()
    return render_template_string(t)
`, `GET /a flask auth=none params=0 dynamic=false handler=h:10
  sql .execute line=12 dynamic=true parameterized=false indirect=false
  sql .execute line=14 dynamic=true parameterized=false indirect=false
  template flask.render_template_string line=18 dynamic=true parameterized=false indirect=false
  sql .execute line=4 dynamic=true parameterized=true indirect=true
GET /b flask auth=none params=0 dynamic=false handler=h:10
  sql .execute line=12 dynamic=true parameterized=false indirect=false
  sql .execute line=14 dynamic=true parameterized=false indirect=false
  template flask.render_template_string line=18 dynamic=true parameterized=false indirect=false
  sql .execute line=4 dynamic=true parameterized=true indirect=true
`},
	{"empty file", ``, ``},
}

func TestExtractPython(t *testing.T) {
	for _, c := range extractCases {
		t.Run(c.name, func(t *testing.T) {
			if got := summarize(extractSource(t, c.src)); got != c.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, c.want)
			}
		})
	}
}

func TestAddPythonRejectsBadInput(t *testing.T) {
	p := testParser(t)
	js, err := p.Parse(context.Background(), JavaScript, []byte("app.get('/x', f)\n"))
	if err != nil {
		t.Fatal(err)
	}
	src := []byte("x = 1\n")
	py, err := p.Parse(context.Background(), Python, src)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		tree *Tree
		src  []byte
	}{
		{"nil tree", nil, src},
		{"no root", &Tree{Language: Python}, src},
		{"not python", js, src},
		{"source shorter than tree", py, src[:2]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := NewExtractor()
			if err := e.AddPython("a.py", c.tree, c.src); err == nil {
				t.Fatal("want error")
			}
			if len(e.Graph().Files) != 0 {
				t.Error("rejected file was added")
			}
		})
	}
}

// TestGraphHoldsNoStrings is the structural guard for the planner boundary:
// no type reachable from Graph can carry text.
func TestGraphHoldsNoStrings(t *testing.T) {
	for _, p := range textCapable(reflect.TypeFor[Graph]()) {
		t.Errorf("%s can carry text; Graph must hold only IDs, enums, booleans and counts", p)
	}
}

// TestTextCapableCatchesEveryTextShape keeps the guard itself honest:
// byte and rune slices or arrays are text as much as string is.
func TestTextCapableCatchesEveryTextShape(t *testing.T) {
	type enum uint8
	cases := []struct {
		name string
		ty   reflect.Type
		want bool
	}{
		{"string", reflect.TypeFor[struct{ S string }](), true},
		{"byte slice", reflect.TypeFor[struct{ B []byte }](), true},
		{"byte array", reflect.TypeFor[struct{ B [4]uint8 }](), true},
		{"rune slice", reflect.TypeFor[struct{ R []rune }](), true},
		{"named byte slice", reflect.TypeFor[struct{ B []enum }](), true},
		{"nested in slice of structs", reflect.TypeFor[struct{ S []struct{ R [2]int32 } }](), true},
		{"pointer", reflect.TypeFor[struct{ P *int }](), true},
		{"interface", reflect.TypeFor[struct{ A any }](), true},
		{"map", reflect.TypeFor[struct{ M map[int]int }](), true},
		{"enums, IDs and bools", reflect.TypeFor[struct {
			E enum
			I []uint32
			B bool
		}](), false},
	}
	for _, c := range cases {
		if got := len(textCapable(c.ty)) > 0; got != c.want {
			t.Errorf("%s: text-capable=%v, want %v", c.name, got, c.want)
		}
	}
}

// textCapable lists the paths in ty that could hold repository text.
func textCapable(ty reflect.Type) []string {
	var out []string
	seen := map[reflect.Type]bool{}
	var check func(reflect.Type, string)
	check = func(ty reflect.Type, path string) {
		if seen[ty] {
			return
		}
		seen[ty] = true
		switch ty.Kind() {
		case reflect.String, reflect.Interface, reflect.Pointer, reflect.Map, reflect.Func, reflect.Chan, reflect.UnsafePointer:
			out = append(out, path)
		case reflect.Slice, reflect.Array:
			if k := ty.Elem().Kind(); k == reflect.Uint8 || k == reflect.Int32 {
				out = append(out, path) // []byte, [N]uint8, []rune
				return
			}
			check(ty.Elem(), path+"[]")
		case reflect.Struct:
			for i := range ty.NumField() {
				f := ty.Field(i)
				check(f.Type, path+"."+f.Name)
			}
		}
	}
	check(ty, ty.String())
	return out
}

// TestHostileTextStaysOutOfGraph plants an instruction in every place repo
// text can appear and checks the serialized graph never carries it.
func TestHostileTextStaysOutOfGraph(t *testing.T) {
	const marker = "IGNOREPREVIOUSINSTRUCTIONS"
	src := `from flask import Flask, Blueprint
app = Flask(__name__)
bp = Blueprint("` + marker + `", __name__, url_prefix="/` + marker + `")
@bp.route("/` + marker + `/<` + marker + `>", methods=["` + marker + `"])
def ` + marker + `():
    ` + marker + ` = "` + marker + `"
    return db.execute(` + marker + `)
app.register_blueprint(bp)
`
	tree, err := testParser(t).Parse(context.Background(), Python, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	e := NewExtractor()
	if err := e.AddPython(marker+".py", tree, []byte(src)); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(e.Graph())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(string(out)), marker) {
		t.Errorf("graph carries repository text: %s", out)
	}
	if len(e.Graph().Routes) != 1 || !strings.Contains(e.Locations().Routes[0].Path, marker) {
		t.Errorf("locations lost the route: %+v", e.Locations())
	}
}

func TestEnumStrings(t *testing.T) {
	cases := []struct{ got, want string }{
		{Methods(0).String(), ""},
		{(MethodGet | MethodTrace | MethodOther).String(), "GET|TRACE|OTHER"},
		{AuthVia(0).String(), "none"},
		{(AuthDecorator | AuthCall).String(), "decorator|call"},
		{Framework(0).String(), "unknown"},
		{SinkKind(0).String(), "unknown"},
		{SinkAPI(0).String(), "unknown"},
		{SinkAPI(255).String(), "unknown"},
		{SinkAPI(255).Kind().String(), "unknown"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	if !errors.Is(ErrGraphFull, ErrGraphFull) || fits(1<<33) {
		t.Error("fits must refuse IDs past 32 bits")
	}
}
