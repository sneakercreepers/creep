package discover

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// classKind maps expected.json classes to the sink kind of their line.
// idor and missing_auth name a route whose data call is the line; they get
// no kind from expected.json, so any candidate on the line counts.
// prototype_pollution has no planner sink kind at all.
var classKind = map[string]SinkKind{
	"sqli": SinkSQL, "command_injection": SinkShell, "path_traversal": SinkFile,
	"ssrf": SinkHTTPClient, "nosql_injection": SinkNoSQL,
	"idor": 0, "missing_auth": 0,
}

type expectedFinding struct {
	Class string `json:"class"`
	File  string `json:"file"`
	Line  int    `json:"line"`
	Route string `json:"route"`
}

// testApp is one testdata app's vulnerable variant and its findings.
type testApp struct {
	name     string
	file     string
	findings []expectedFinding
	lines    []string
}

func testApps(t *testing.T) []testApp {
	t.Helper()
	dirs, err := os.ReadDir(appsDir)
	if err != nil {
		t.Fatal(err)
	}
	var apps []testApp
	for _, d := range dirs {
		if d.IsDir() {
			apps = append(apps, loadApp(t, d.Name()))
		}
	}
	if len(apps) == 0 {
		t.Fatal("no testdata apps")
	}
	return apps
}

func loadApp(t *testing.T, name string) testApp {
	t.Helper()
	var exp struct {
		App        string            `json:"app"`
		Vulnerable []expectedFinding `json:"vulnerable"`
	}
	data, err := os.ReadFile(filepath.Join(appsDir, name, "expected.json"))
	if err == nil {
		err = json.Unmarshal(data, &exp)
	}
	if err != nil || exp.App != name || len(exp.Vulnerable) == 0 {
		t.Fatalf("%s/expected.json: %v", name, err)
	}
	app := testApp{name: name, file: exp.Vulnerable[0].File, findings: exp.Vulnerable}
	for _, f := range exp.Vulnerable {
		if f.File != app.file {
			t.Fatalf("%s: findings in several files; the fixtures hold one batch per app", name)
		}
	}
	src, err := os.ReadFile(filepath.Join(appsDir, name, variantVulnerable, app.file))
	if err != nil {
		t.Fatal(err)
	}
	app.lines = splitLines(string(src))
	return app
}

// routeLine is the line that declares route: the first holding it quoted
// (a decorator or a router call).
func (a testApp) routeLine(route string) int {
	for i, l := range a.lines {
		if strings.Contains(l, `"`+route+`"`) {
			return i + 1
		}
	}
	return 0
}

func (a testApp) routes() []string {
	var out []string
	for _, f := range a.findings {
		if !slices.Contains(out, f.Route) {
			out = append(out, f.Route)
		}
	}
	return out
}

// synthesizedReply is what the fixtures record; no live model is called.
// For the app's file it proposes each expected.json route at its line
// (and the next, the handler's def) and each finding with a sink kind at
// its line, linked to its route; for the canary, its entry and sink.
func synthesizedReply(app testApp, secs []promptSection) ([]byte, error) {
	a := honest(secs)
	c, _ := canaryOf(secs)
	for _, s := range secs {
		if s.num != c.section {
			app.propose(&a, s.num)
		}
	}
	return json.Marshal(a)
}

// propose appends the app's routes and sinks for batch file index file;
// a sink links to its route's index in ans.Entries.
func (a testApp) propose(ans *Answer, file int) {
	first := len(ans.Entries)
	routes := a.routes()
	for _, r := range routes {
		line := a.routeLine(r)
		ans.Entries = append(ans.Entries, entryAt(file, line, line+1, "http"))
	}
	for _, fd := range a.findings {
		if kind, ok := classKind[fd.Class]; ok && kind != 0 {
			entry := first + slices.Index(routes, fd.Route) // routes holds every finding's route
			ans.Sinks = append(ans.Sinks, sinkAt(file, fd.Line, kind.String(), entry))
		}
	}
}

// recall counts what a Result finds of an app's expected.json.
type recall struct {
	routes, routesFound     int
	sinks, sinksFound       int // findings with a planner sink line
	tripwireFound           int // of those, found by the tripwire alone
	noKind, noKindCandidate int // findings with no planner sink kind
}

func (r *recall) add(o recall) {
	r.routes += o.routes
	r.routesFound += o.routesFound
	r.sinks += o.sinks
	r.sinksFound += o.sinksFound
	r.tripwireFound += o.tripwireFound
	r.noKind += o.noKind
	r.noKindCandidate += o.noKindCandidate
}

// score measures res against app. A route is found when a proposed entry
// covers its line; a sink when a candidate sits on its line with its kind
// (any kind for idor and missing_auth).
func score(app testApp, res Result) recall {
	var r recall
	for _, route := range app.routes() {
		r.routes++
		line := uint32(app.routeLine(route)) //nolint:gosec // G115: small files
		if slices.ContainsFunc(res.Routes, func(rt Route) bool { return !rt.FileLevel && rt.Lines.Start <= line && line <= rt.Lines.End }) {
			r.routesFound++
		}
	}
	for _, f := range app.findings {
		kind, ok := classKind[f.Class]
		found := func(origin Origin) bool {
			return slices.ContainsFunc(res.Sinks, func(s Sink) bool {
				return int(s.Line) == f.Line && (kind == 0 || s.Kind == kind) && s.Origin&origin != 0
			})
		}
		if !ok {
			r.noKind++
			if found(OriginTripwire | OriginModel) {
				r.noKindCandidate++
			}
			continue
		}
		r.sinks++
		if found(OriginTripwire | OriginModel) {
			r.sinksFound++
		}
		if found(OriginTripwire) {
			r.tripwireFound++
		}
	}
	return r
}

// TestRecallOnTestdataApps measures tripwire plus replayed discovery
// against every expected.json (#265 D4). With the committed fixtures the
// model part is synthesized from expected.json itself, so its recall is
// SYNTHESIZED, NOT A QUALITY MEASURE: it proves the path keeps what a
// model proposes. The tripwire column is real: the table alone, with no
// model. Score a store recorded from a real model with -fixtures.
func TestRecallOnTestdataApps(t *testing.T) {
	var total recall
	for _, app := range testApps(t) {
		r := score(app, replayApp(t, app))
		t.Logf("%-8s routes %d/%d, sinks %d/%d (tripwire alone %d/%d), no planner kind %d (candidate on line %d)",
			app.name, r.routesFound, r.routes, r.sinksFound, r.sinks, r.tripwireFound, r.sinks, r.noKind, r.noKindCandidate)
		total.add(r)
	}
	t.Logf("all      routes %d/%d, sinks %d/%d (tripwire alone %d/%d), no planner kind %d (candidate on line %d); fixtures %s (synthesized unless -fixtures says otherwise)",
		total.routesFound, total.routes, total.sinksFound, total.sinks, total.tripwireFound, total.sinks, total.noKind, total.noKindCandidate, *fixtures)
	if total.routesFound != total.routes || total.sinksFound != total.sinks {
		t.Errorf("recall below 100%%: %s", fmt.Sprintf("%+v", total))
	}
	if total.tripwireFound != total.sinks {
		t.Errorf("the tripwire alone misses an expected sink line: %+v", total)
	}
}

// The synthesized model must see each route where the replay expects it,
// so a moved line in an app fails here, not as a confusing recall miss.
func TestAppRoutesAreInFile(t *testing.T) {
	for _, app := range testApps(t) {
		for _, r := range app.routes() {
			if line := app.routeLine(r); line == 0 || line >= len(app.lines) {
				t.Errorf("%s: route %s not found in %s", app.name, r, app.file)
			}
		}
		for _, f := range app.findings {
			if f.Line < 1 || f.Line > len(app.lines) || strings.TrimSpace(app.lines[f.Line-1]) == "" {
				t.Errorf("%s: finding line %d is not code", app.name, f.Line)
			}
		}
	}
}

// TestTripwireRecall is the amended D4 sink gate: the tripwire alone, with
// no model and no replay, must put a candidate on every expected.json sink
// line that has a planner kind (idor and missing_auth: any kind). It runs
// the table on the raw files, which redaction leaves unchanged. Safe twins
// are reported, not failed: a hit is a candidate for the reader, never a
// verdict, and the twins keep the same calls (execFile, findOne,
// send_from_directory, a parameterized execute) made safe by context a
// byte match cannot see.
func TestTripwireRecall(t *testing.T) {
	rows, err := loadTripwire()
	if err != nil {
		t.Fatal(err)
	}
	found, total, missed := 0, 0, []string{}
	for _, app := range testApps(t) {
		hits, _ := tripwire(rows, []byte(strings.Join(app.lines, "\n")))
		appFound, appTotal := 0, 0
		for _, f := range app.findings {
			kind, ok := classKind[f.Class]
			if !ok {
				missed = append(missed, fmt.Sprintf("%s:%d %s (no planner sink kind)", app.name, f.Line, f.Class))
				continue
			}
			appTotal++
			if slices.ContainsFunc(hits, func(h hit) bool { return int(h.line) == f.Line && (kind == 0 || h.kind == kind) }) {
				appFound++
				continue
			}
			missed = append(missed, fmt.Sprintf("%s:%d %s", app.name, f.Line, f.Class))
		}
		t.Logf("%-8s tripwire alone: sinks %d/%d; candidate lines: %d in the vulnerable file, %d in the safe twin",
			app.name, appFound, appTotal, len(hits), len(safeTwinHits(t, rows, app)))
		found, total = found+appFound, total+appTotal
	}
	t.Logf("all      tripwire alone: sinks %d/%d; not counted or missed: %v", found, total, missed)
	if found != total {
		t.Errorf("the tripwire alone misses expected sink lines: %v", missed)
	}
}

func safeTwinHits(t *testing.T, rows []signature, app testApp) []hit {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(appsDir, app.name, "safe", app.file))
	if err != nil {
		t.Fatal(err)
	}
	hits, _ := tripwire(rows, src)
	return hits
}
