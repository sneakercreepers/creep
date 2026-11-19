package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/scanrun"
	"github.com/sneakercreepers/creep/internal/static"
)

// helloRoute is a Flask route with no sink: static extracts a route, so a
// run over it can be complete.
const helloRoute = "from flask import Flask\n\napp = Flask(__name__)\n\n@app.route(\"/\")\ndef index():\n    return \"ok\"\n"

// djangoViews is string-built SQL behind a Django view, a framework static
// does not extract routes for (#207).
var djangoViews = map[string]string{
	"shop/views.py": "from django.db import connection\nfrom django.http import HttpResponse\n\n" +
		"def search(request):\n    q = request.GET[\"q\"]\n    with connection.cursor() as c:\n" +
		"        c.execute(\"SELECT * FROM items WHERE name = '\" + q + \"'\")\n        return HttpResponse(str(c.fetchall()))\n",
	"shop/urls.py": "from django.urls import path\n\nfrom . import views\n\nurlpatterns = [path(\"search/\", views.search)]\n",
}

// #207: when static extracts no route (and so no sink), no class is
// covered and the run never exits 0 as clean; text and Markdown name the
// frameworks static looked in. A repository with a route still reads as
// complete, findings or not.
func TestScanNoRoutesIsNotCovered(t *testing.T) {
	tests := []struct {
		name       string
		files      map[string]string
		wantCode   int
		wantReason string // "" means complete
		noRoutes   bool
	}{
		{"django only", djangoViews, exitcode.Incomplete, reasonNoRoutes, true},
		{"python without routes", map[string]string{"tool.py": "import os\nimport sys\n\nos.system(sys.argv[1])\n"}, exitcode.Incomplete, reasonNoRoutes, true},
		{"javascript without express", map[string]string{"server.js": "const http = require(\"http\");\nhttp.createServer((req, res) => res.end(req.url)).listen(80);\n"}, exitcode.Incomplete, reasonNoRoutes, true},
		{"empty repository", map[string]string{}, exitcode.Incomplete, reasonNoRoutes, true},
		{"only non-source files", map[string]string{"README.md": "# x\n", "config.yaml": "a: 1\n"}, exitcode.Incomplete, reasonNoRoutes, true},
		{"only by-design vendor code", map[string]string{"node_modules/app/package.json": "{}", "node_modules/app/index.js": "x()\n"}, exitcode.Incomplete, reasonNoRoutes, true},
		{"file gap names its reason first", map[string]string{"broken.py": "def f(:\n"}, exitcode.Incomplete, string(report.SkipSyntaxError), true},
		{"flask route without sinks", map[string]string{"app.py": helloRoute}, exitcode.OK, "", false},
		{"flask app without findings", map[string]string{"app.py": "@flask"}, exitcode.OK, "", false},
		{"one routed file among route-free ones", map[string]string{"app.py": helloRoute, "tool.py": "import os\n"}, exitcode.OK, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, tt.files, "")
			m := &fakeModel{}
			code, out, errOut := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--config", cfg)
			if code != tt.wantCode {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, tt.wantCode, out, errOut)
			}
			checkJSONReport(t, tt.wantReason)
			checkNoRoutesOutput(t, out, tt.noRoutes)
			checkClassStatuses(t, tt.noRoutes)
			if tt.noRoutes && m.calls != 0 {
				t.Errorf("%d reader calls with no route to read", m.calls)
			}
		})
	}
}

// checkNoRoutesOutput wants the frameworks named in the text summary and
// in .creep/report.md exactly when static found no route.
func checkNoRoutesOutput(t *testing.T, out string, noRoutes bool) {
	t.Helper()
	frameworks := strings.Join(static.FrameworkNames(), "/")
	md, err := os.ReadFile(filepath.Join(stateDir, reportNames["markdown"]))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Contains(out, "routes: no "+frameworks+" routes found"); got != noRoutes {
		t.Errorf("text names the frameworks: %v, want %v\n%s", got, noRoutes, out)
	}
	if got := strings.Contains(string(md), "**No "+frameworks+" routes found.**"); got != noRoutes {
		t.Errorf("Markdown names the frameworks: %v, want %v\n%s", got, noRoutes, md)
	}
	if noRoutes {
		checkNoCoverageClaim(t, out, string(md))
	}
}

// checkNoCoverageClaim wants a run with no route never to read as if
// everything was evaluated (#248): no "0 not evaluated" in the text, no
// "Every file was evaluated" in Markdown, and the mark says why.
func checkNoCoverageClaim(t *testing.T, out, md string) {
	t.Helper()
	for _, claim := range []string{"0 not evaluated", "Every file was evaluated"} {
		if strings.Contains(out, claim) || strings.Contains(md, claim) {
			t.Errorf("a run with no route claims %q\ntext:\n%s\nMarkdown:\n%s", claim, out, md)
		}
	}
	if !strings.Contains(out, "static found no route, so no class was evaluated") {
		t.Errorf("incomplete mark does not say no route was found:\n%s", out)
	}
	if !strings.Contains(md, "Static analysis found no route, so no file was evaluated") {
		t.Errorf("Markdown Not evaluated section does not say no route was found:\n%s", md)
	}
}

// checkClassStatuses wants every class not evaluated when there was no
// route, and every readable class covered otherwise.
func checkClassStatuses(t *testing.T, noRoutes bool) {
	t.Helper()
	rep, err := readLastReport()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Coverage.Classes {
		want := report.ClassNotEvaluated
		if !noRoutes && readClasses[c.Class] {
			want = report.ClassCovered
		}
		if c.Status != want {
			t.Errorf("class %s %s, want %s", c.Class, c.Status, want)
		}
	}
}

// The incomplete mark reaches stderr with a report on stdout, and the
// gate cannot turn a run with no route into exit 0 or 1.
func TestScanNoRoutesOtherFormats(t *testing.T) {
	for _, format := range []string{"json", "sarif", "markdown"} {
		t.Run(format, func(t *testing.T) {
			cfg := scanRepo(t, djangoViews, "gates:\n  pr: none\n")
			code, _, errOut := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--format", format, "--config", cfg)
			if code != exitcode.Incomplete || !strings.Contains(errOut, "INCOMPLETE RUN (reason no_routes): static found no route") {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			if strings.Contains(errOut, "0 not evaluated") {
				t.Errorf("stderr mark claims nothing was left out: %q", errOut)
			}
		})
	}
}

// ADR 0009 amendment: no_routes comes after the file gaps and before a
// failed scanner, so swapping the checks in buildReport fails here (#248).
// The scanner still runs and is listed failed whatever the reason.
func TestNoRoutesReasonOrder(t *testing.T) {
	tests := []struct {
		name   string
		files  map[string]string
		reason string
	}{
		{"no route ahead of a failed scanner", djangoViews, reasonNoRoutes},
		{"file gap ahead of no route and a failed scanner", map[string]string{"broken.py": "def f(:\n"}, string(report.SkipSyntaxError)},
		{"failed scanner when a route was found", map[string]string{"app.py": helloRoute}, reasonScannerFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, tt.files, "scanners:\n  enabled: [gitleaks]\n")
			t.Setenv("PATH", placeTool(t, "gitleaks"))
			deps := fakeDeps(&fakeModel{}, calibrate.TierM)
			deps.runScanner = func(context.Context, scanrun.Job) scanrun.Result {
				return scanrun.Result{Outcome: scanrun.Failed, Failure: scanrun.FailTimeout}
			}
			code, out, errOut := runScanWith(deps, "scan", "--config", cfg)
			if code != exitcode.Incomplete || !strings.Contains(out, "scanner gitleaks: failed") {
				t.Fatalf("exit %d, want %d with gitleaks failed\nstdout:\n%s\nstderr:\n%s", code, exitcode.Incomplete, out, errOut)
			}
			checkJSONReport(t, tt.reason)
		})
	}
}
