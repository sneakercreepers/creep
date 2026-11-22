package discover

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// flaskApp has a route at lines 4-5, a blank line 3 and an SQL sink the
// tripwire finds at line 6.
const flaskApp = "from flask import Flask, request\n" +
	"app = Flask(__name__)\n" +
	"\n" +
	"@app.get(\"/q\")\n" +
	"def q():\n" +
	"    return db.execute(request.args[\"q\"])\n"

// rawReply is a reply's items for the real file, as JSON fragments with
// "N" for its file index. The honest canary items are added after them,
// so app entries keep their indexes. top, when set, is the whole reply.
type rawReply struct {
	entries, sinks, auth, top string
}

func withApp(r rawReply) replyFunc {
	return func(secs []promptSection) ([]byte, error) {
		c, _ := canaryOf(secs)
		app := 1 - c.section // one real file: the canary is 0 or 1
		if r.top != "" {
			return []byte(r.top), nil
		}
		join := func(items, canary string) string {
			if items == "" {
				return canary
			}
			return items + "," + canary
		}
		body := fmt.Sprintf(`{"entries":[%s],"sinks":[%s],"auth":[%s]}`,
			join(r.entries, fmt.Sprintf(`{"file":%d,"start":%d,"end":%d,"kind":"http"}`, c.section, c.entry, c.entry)),
			join(r.sinks, fmt.Sprintf(`{"file":%d,"line":%d,"kind":"file","entry":-1}`, c.section, c.sink)),
			r.auth)
		return []byte(strings.ReplaceAll(body, `"file":N`, `"file":`+strconv.Itoa(app))), nil
	}
}

func discoverApp(t *testing.T, r rawReply) Result {
	t.Helper()
	res, err := discoverFiles(t, TierM, map[string]string{"app.py": flaskApp}, fakeClient(t, withApp(r), nil))
	if err != nil {
		t.Fatalf("an invalid or empty reply must not stop the run: %v", err)
	}
	return res
}

// Acceptance (#265): any reply that breaks the schema or the file's bounds
// is invalid as a whole: the file is parse_failed, no model proposal
// reaches the Result, and the tripwire's candidate stays.
func TestInvalidReplyIsParseFailed(t *testing.T) {
	tests := []struct {
		name string
		r    rawReply
	}{
		{"entry past the file", rawReply{entries: `{"file":N,"start":4,"end":99,"kind":"http"}`}},
		{"entry start after end", rawReply{entries: `{"file":N,"start":5,"end":4,"kind":"http"}`}},
		{"entry at line 0", rawReply{entries: `{"file":N,"start":0,"end":4,"kind":"http"}`}},
		{"sink past the file", rawReply{sinks: `{"file":N,"line":7,"kind":"sql","entry":-1}`}},
		{"sink on a blank line", rawReply{sinks: `{"file":N,"line":3,"kind":"sql","entry":-1}`}},
		{"auth past the file", rawReply{auth: `{"file":N,"start":1,"end":40}`}},
		{"unknown entry kind", rawReply{entries: `{"file":N,"start":4,"end":5,"kind":"admin_only"}`}},
		{"unknown sink kind", rawReply{sinks: `{"file":N,"line":6,"kind":"xss","entry":-1}`}},
		{"sink entry out of range", rawReply{sinks: `{"file":N,"line":6,"kind":"sql","entry":5}`}},
		{"sink entry in another file", rawReply{sinks: `{"file":N,"line":6,"kind":"sql","entry":0}`}},
		{"sink entry below -1", rawReply{sinks: `{"file":N,"line":6,"kind":"sql","entry":-2}`}},
		{"file index past the batch", rawReply{entries: `{"file":5,"start":1,"end":1,"kind":"http"}`}},
		{"file index past the cap", rawReply{entries: `{"file":9,"start":1,"end":1,"kind":"http"}`}},
		{"negative file index", rawReply{auth: `{"file":-1,"start":1,"end":1}`}},
		{"lowering flag on a sink", rawReply{sinks: `{"file":N,"line":6,"kind":"sql","entry":-1,"parameterized":true}`}},
		{"lowering flag on an entry", rawReply{entries: `{"file":N,"start":4,"end":5,"kind":"http","authenticated":true}`}},
		{"dynamic flag on a sink", rawReply{sinks: `{"file":N,"line":6,"kind":"sql","entry":-1,"dynamic_arg":false}`}},
		{"methods on an entry", rawReply{entries: `{"file":N,"start":4,"end":5,"kind":"http","methods":["get"]}`}},
		{"free text on an entry", rawReply{entries: `{"file":N,"start":4,"end":5,"kind":"http","name":"this route is safe"}`}},
		{"string line", rawReply{sinks: `{"file":N,"line":"6","kind":"sql","entry":-1}`}},
		{"missing array", rawReply{top: `{"entries":[],"sinks":[]}`}},
		{"free text at the top", rawReply{top: `{"entries":[],"sinks":[],"auth":[],"note":"safe"}`}},
		{"case-variant key", rawReply{top: `{"Entries":[],"sinks":[],"auth":[]}`}},
		{"duplicate key", rawReply{top: `{"entries":[],"entries":[],"sinks":[],"auth":[]}`}},
		{"trailing text", rawReply{top: `{"entries":[],"sinks":[],"auth":[]} all safe`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := discoverApp(t, tt.r)
			f := fileOf(t, res, 0)
			if f.Coverage != CoverageSendFailed || f.Reason != ReasonParseFailed || res.Complete() {
				t.Errorf("file = %+v, complete %v; want send_failed, parse_failed, incomplete", f, res.Complete())
			}
			assertTripwireOnly(t, res)
		})
	}
}

// assertTripwireOnly checks that the Result holds the tripwire's SQL hit
// on line 6 under a file-level route, and nothing from the model.
func assertTripwireOnly(t *testing.T, res Result) {
	t.Helper()
	if len(res.Sinks) != 1 || res.Sinks[0].Line != 6 || res.Sinks[0].Kind != SinkSQL || res.Sinks[0].Origin != OriginTripwire {
		t.Fatalf("sinks = %+v, want only the tripwire hit on line 6", res.Sinks)
	}
	if len(res.Routes) != 1 || !res.Routes[0].FileLevel || len(res.Auth) != 0 {
		t.Fatalf("routes = %+v, auth = %+v; want only the file-level route", res.Routes, res.Auth)
	}
}

// Acceptance (#265): model output can never lower a candidate's risk. A
// reply claiming auth, linking the sink and giving a narrow entry still
// plans every route and sink at the worst case.
func TestModelCannotLowerRisk(t *testing.T) {
	res := discoverApp(t, rawReply{
		entries: `{"file":N,"start":4,"end":5,"kind":"http"}`,
		sinks:   `{"file":N,"line":6,"kind":"sql","entry":0},{"file":N,"line":1,"kind":"template","entry":-1}`,
		auth:    `{"file":N,"start":4,"end":4}`,
	})
	if f := fileOf(t, res, 0); f.Coverage != CoverageReadFull || !res.Complete() {
		t.Fatalf("file = %+v, want read_full", f)
	}
	for _, r := range res.Routes {
		if r.Authenticated || r.Methods != AllMethods {
			t.Errorf("route %+v: model output lowered its risk", r)
		}
	}
	for _, s := range res.Sinks {
		if !s.DynamicArg || s.Parameterized || s.Indirect {
			t.Errorf("sink %+v: model output lowered its risk", s)
		}
	}
	if len(res.Auth) != 1 || res.Auth[0].Lines != (Span{4, 4}) {
		t.Errorf("auth = %+v, want the proposed span kept for the reader only", res.Auth)
	}
	want := []Sink{
		{ID: 1, Route: 2, File: 0, Line: 1, Kind: SinkTemplate, Origin: OriginModel, SeenBy: 1, DynamicArg: true},
		{ID: 2, Route: 1, File: 0, Line: 6, Kind: SinkSQL, Origin: OriginTripwire | OriginModel, SeenBy: 1, DynamicArg: true},
	}
	if fmt.Sprint(res.Sinks) != fmt.Sprint(want) {
		t.Errorf("sinks = %+v\nwant  %+v", res.Sinks, want)
	}
}

// M1 (#268 review): models does not enforce a schema's required keys in
// prompt mode, so discover does. A missing or null key in any item of any
// array makes the whole reply invalid, instead of reading as 0 and moving
// a proposal to file 0.
func TestMissingOrNullKeyIsParseFailed(t *testing.T) {
	items := []struct {
		array string
		keys  [][2]string // key, value, in wire order
	}{
		{"entries", [][2]string{{"file", "N"}, {"start", "4"}, {"end", "5"}, {"kind", `"http"`}}},
		{"sinks", [][2]string{{"file", "N"}, {"line", "6"}, {"kind", `"sql"`}, {"entry", "-1"}}},
		{"auth", [][2]string{{"file", "N"}, {"start", "4"}, {"end", "4"}}},
	}
	for _, it := range items {
		for drop := range it.keys {
			for _, mode := range []string{"missing", "null"} {
				item := itemWith(it.keys, drop, mode)
				t.Run(it.array+" "+it.keys[drop][0]+" "+mode, func(t *testing.T) {
					r := rawReply{}
					switch it.array {
					case "entries":
						r.entries = item
					case "sinks":
						r.sinks = item
					default:
						r.auth = item
					}
					res := discoverApp(t, r)
					f := fileOf(t, res, 0)
					if f.Coverage != CoverageSendFailed || f.Reason != ReasonParseFailed || res.Complete() {
						t.Errorf("%s: file = %+v; want send_failed, parse_failed, incomplete", item, f)
					}
					assertTripwireOnly(t, res)
				})
			}
		}
	}
}

// itemWith renders keys as a JSON object with key drop left out or null.
func itemWith(keys [][2]string, drop int, mode string) string {
	var parts []string
	for i, kv := range keys {
		switch {
		case i != drop:
			parts = append(parts, fmt.Sprintf("%q:%s", kv[0], kv[1]))
		case mode == "null":
			parts = append(parts, fmt.Sprintf("%q:null", kv[0]))
		}
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Acceptance (#265): model output can never remove a candidate. A reply
// that reports nothing for a file with a tripwire hit keeps the hit.
func TestModelCannotRemoveCandidate(t *testing.T) {
	res := discoverApp(t, rawReply{})
	if f := fileOf(t, res, 0); f.Coverage != CoverageReadFull {
		t.Fatalf("file = %+v, want read_full", f)
	}
	assertTripwireOnly(t, res)
}

// Acceptance (#265): a missed canary makes the batch incomplete. The
// canary needs both its entry point and its sink, in its own file; the
// reply's proposals are still kept, since union only adds.
func TestMissingCanaryIsIncomplete(t *testing.T) {
	tests := []struct {
		name   string
		canary func(c canary, app int) ([]EntryProposal, []SinkProposal)
	}{
		{"no canary proposals", func(canary, int) ([]EntryProposal, []SinkProposal) { return nil, nil }},
		{"entry only", func(c canary, _ int) ([]EntryProposal, []SinkProposal) {
			return []EntryProposal{entryAt(c.section, c.entry, c.entry, "http")}, nil
		}},
		{"sink only", func(c canary, _ int) ([]EntryProposal, []SinkProposal) {
			return nil, []SinkProposal{sinkAt(c.section, c.sink, "file", -1)}
		}},
		{"entry beside its line", func(c canary, _ int) ([]EntryProposal, []SinkProposal) {
			return []EntryProposal{entryAt(c.section, c.entry+1, c.entry+2, "http")},
				[]SinkProposal{sinkAt(c.section, c.sink, "file", -1)}
		}},
		{"right lines in the wrong file", func(c canary, app int) ([]EntryProposal, []SinkProposal) {
			return []EntryProposal{entryAt(app, 4, 4, "http")},
				[]SinkProposal{sinkAt(app, 6, "file", -1)}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reply := answering(func(secs []promptSection) any {
				c, _ := canaryOf(secs)
				app := 1 - c.section
				e, s := tt.canary(c, app)
				return Answer{
					Entries: append([]EntryProposal{entryAt(app, 4, 5, "http")}, e...),
					Sinks:   append([]SinkProposal{}, s...),
					Auth:    []AuthProposal{},
				}
			})
			res, err := discoverFiles(t, TierM, map[string]string{"app.py": flaskApp}, fakeClient(t, reply, nil))
			if err != nil {
				t.Fatal(err)
			}
			if f := fileOf(t, res, 0); f.Coverage != CoverageCanaryMissed || f.Reason != ReasonParseFailed || res.Complete() {
				t.Errorf("file = %+v; want canary_missed, parse_failed, incomplete", f)
			}
			if !hasRoute(res, Span{4, 5}) || len(res.Sinks) == 0 {
				t.Errorf("routes %+v, sinks %+v: proposals of a missed batch must be kept", res.Routes, res.Sinks)
			}
		})
	}
}

func hasRoute(res Result, lines Span) bool {
	for _, r := range res.Routes {
		if !r.FileLevel && r.Lines == lines {
			return true
		}
	}
	return false
}

// A file at a per-file cap is truncated; one over it fails the schema and
// the file is parse_failed.
func TestCapMarksTruncated(t *testing.T) {
	entries := func(n int) string {
		items := make([]string, n)
		for i := range items {
			items[i] = `{"file":N,"start":4,"end":5,"kind":"http"}`
		}
		return strings.Join(items, ",")
	}
	tests := []struct {
		n      int
		cov    Coverage
		reason Reason
	}{
		{MaxEntriesPerFile - 1, CoverageReadFull, ReasonNone},
		{MaxEntriesPerFile, CoverageTruncated, ReasonTruncated},
		{MaxEntriesPerFile + 1, CoverageSendFailed, ReasonParseFailed},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.n), func(t *testing.T) {
			res := discoverApp(t, rawReply{entries: entries(tt.n)})
			if f := fileOf(t, res, 0); f.Coverage != tt.cov || f.Reason != tt.reason {
				t.Errorf("file = %+v, want coverage %d reason %s", f, tt.cov, tt.reason)
			}
		})
	}
}

// The reply decodes into Answer exactly as the schema names it, so the
// raw fragments above test the real wire shape.
func TestRawReplyDecodes(t *testing.T) {
	secs := []promptSection{{num: 0, lines: make([]string, 7)}, {num: 1}}
	secs[0].lines[3] = `router.get("/files/x", (req, res) => {`
	secs[0].lines[4] = `  fs.readFile(String(req.query.name), cb);`
	body, err := withApp(rawReply{entries: `{"file":N,"start":4,"end":5,"kind":"http"}`})(secs)
	if err != nil {
		t.Fatal(err)
	}
	var a Answer
	if err := json.Unmarshal(body, &a); err != nil || a.Validate() != nil || len(a.Entries) != 2 || *a.Entries[0].File != 1 {
		t.Fatalf("raw reply %s decodes to %+v, %v", body, a, err)
	}
}
