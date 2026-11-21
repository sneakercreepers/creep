package verify

import (
	"context"
	"errors"
	"html"
	"strings"
	"testing"
	"time"
)

const reflectFixture, headerFixture = "http_request_reflect", "http_request_header"

// slowFrom answers every request at once until the n-th, then each after
// 3.1 s: a rate limit or tarpit that slows later requests, whatever they
// hold.
func slowFrom(n int) app {
	seen := 0
	return func(string, map[string]bool) (string, time.Duration) {
		seen++
		if seen >= n {
			return ok("[]"), 3100 * time.Millisecond
		}
		return ok("[]"), fast
	}
}

// passwdSample serves a sample passwd file, as a safe app that normalizes
// ../ might from its own docs, whenever the request names the canary.
func passwdSample(req string, _ map[string]bool) (string, time.Duration) {
	if strings.Contains(req, "creep-canary") {
		return ok("root:x:0:0:root:/root:/bin/sh\n"), fast
	}
	return status("404 Not Found"), fast
}

type oracleCase struct {
	fixture string
	app     app
	target  Target
	want    Outcome
}

func reflectionCases() map[string]oracleCase {
	at := Target{Port: testPort}
	p := probe(testNonce)
	return map[string]oracleCase{
		"placeholder echoed":    {reflectFixture, always(page(NoncePlaceholder)), at, NotVerified},
		"another nonce":         {reflectFixture, always(page(probe("creepffffffffffffffffffffffff"))), at, NotVerified},
		"bare nonce reflected":  {reflectFixture, always(page("results for " + testNonce)), at, NotVerified},
		"probe escaped":         {reflectFixture, always(page(html.EscapeString(p))), at, NotVerified},
		"probe, quotes escaped": {reflectFixture, always(page(`&#39;&#34;><` + testNonce + `>`)), at, NotVerified},
		"probe only in headers": {reflectFixture, always("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Echo: " + p + "\r\n\r\n"), at, NotVerified},
		"probe in JSON":         {reflectFixture, always("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + p), at, NotVerified},
		"probe, no type":        {reflectFixture, always("HTTP/1.1 200 OK\r\n\r\n" + p), at, NotVerified},
		"probe, two types":      {reflectFixture, always("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Type: text/plain\r\n\r\n" + p), at, NotVerified},
		"probe, other status":   {headerFixture, always("HTTP/1.1 500 Oops\r\nContent-Type: text/html\r\n\r\n" + p), at, NotVerified},
		"the expected status":   {headerFixture, always(page("<p>hello</p>")), at, NotVerified},
		"empty answer":          {headerFixture, always(""), at, NoResponse},
		"not HTTP":              {headerFixture, always("SSH-2.0-OpenSSH\r\n\r\n"), at, NoResponse},
		"auth refused":          {"http_sequence_cookie", always("HTTP/1.1 401 Unauthorized\r\nSet-Cookie: s=1\r\n\r\n"), at, AuthFailed},
		"auth without session":  {"http_sequence_cookie", always(ok("")), at, AuthFailed},
		"auth not HTTP":         {"http_sequence_bearer", always("garbage"), at, NoResponse},
	}
}

func sideEffectCases() map[string]oracleCase {
	at := Target{Port: testPort}
	otherTable := func(_ string, tables map[string]bool) (string, time.Duration) {
		tables["creep_ffffffffffffffffffffffff"], tables["items"] = true, true
		return ok(""), fast
	}
	canary := canaryApp("")
	silentBaseline := func(req string, tables map[string]bool) (string, time.Duration) {
		if strings.Contains(req, baselineFile) {
			return "", fast
		}
		return canary(req, tables)
	}
	return map[string]oracleCase{
		"slow on every request":   {"sql_payload_delay", slowFrom(1), at, NotVerified},
		"slows the second":        {"sql_payload_delay", slowFrom(2), at, NotVerified},
		"canary everywhere":       {"path_payload_relative", canary, at, NotVerified},
		"passwd at the canary":    {"path_payload_relative", passwdSample, at, NotVerified},
		"no baseline answer":      {"path_payload_relative", silentBaseline, at, NoResponse},
		"another table":           {"sql_payload_marker", otherTable, Target{Port: testPort, Database: true}, NotVerified},
		"no database":             {"sql_payload_marker", otherTable, at, NoDatabase},
		"no answer to the marker": {"sql_payload_marker", always(""), Target{Port: testPort, Database: true}, NoResponse},
	}
}

// TestOraclesCannotBeFaked is the protection test for the oracles: an
// app (or a model's choice of request) that always looks vulnerable, or
// that only reflects input safely, is not verified. A reflection must be
// this run's probe, unescaped, in an HTML body: not the placeholder, the
// bare nonce, another nonce, an escaped probe, a header, JSON or a body
// without a type; the status the model expects never verifies on its
// own; a delay must exceed the baselines on both sides; the canary file's
// content, not a passwd sample, must be in the payload response only; the
// database marker is creep's table, not one the app names; no database or
// no answer is never verified.
func TestOraclesCannotBeFaked(t *testing.T) {
	cases := reflectionCases()
	for name, c := range sideEffectCases() {
		cases[name] = c
	}
	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			runner := newFake(tt.app)
			res, err := runOnce(runner, tt.target, mustBuild(t, loadRequest(t, tt.fixture)))
			if err != nil || res.Outcome != tt.want {
				t.Fatalf("Run = %s, %v; want %s", res.Outcome, err, tt.want)
			}
			if tt.want == NoDatabase && len(runner.sent) != 0 {
				t.Errorf("a marker payload was sent with no database")
			}
			for _, table := range runner.looked {
				if table != markerTable(testNonce) {
					t.Errorf("looked up %s, not creep's marker", table)
				}
			}
		})
	}
}

// TestStatusNeverVerifies: a status oracle, the one a model could satisfy
// by expecting what a harmless request returns, is refused before
// anything runs, and a status beside reflect never verifies without the
// probe.
func TestStatusNeverVerifies(t *testing.T) {
	req := loadRequest(t, headerFixture)
	for _, o := range []Oracle{{Kind: "status", Status: 200}, {Kind: "", Status: 200}, {Kind: "STATUS", Status: 200}} {
		req.HTTPRequest.Oracle = o
		if _, err := Build(req); !errors.Is(err, ErrInvalid) {
			t.Errorf("oracle %+v: Build = %v, want ErrInvalid", o, err)
		}
	}
	for _, code := range []string{"200 OK", "302 Found", "401 Unauthorized", "500 Oops"} {
		poc := mustBuild(t, loadRequest(t, headerFixture))
		res, err := runOnce(newFake(always("HTTP/1.1 "+code+"\r\nContent-Type: text/html\r\n\r\nhi")), Target{Port: testPort}, poc)
		if err != nil || res.Outcome == Verified {
			t.Errorf("status %s alone: %s, %v", code, res.Outcome, err)
		}
	}
}

// TestRunsAreIndependent: each Run has a fresh nonce, so a marker table or
// a stored probe from an earlier run of the same PoC never verifies a
// later one against an app that is no longer vulnerable.
func TestRunsAreIndependent(t *testing.T) {
	poc := mustBuild(t, loadRequest(t, "sql_payload_marker"))
	target := Target{Port: testPort, Database: true}
	runner := newFake(goldenCases["sql_payload_marker"].vulnerable)
	if res, err := Run(context.Background(), runner, target, poc); err != nil || res.Outcome != Verified {
		t.Fatalf("first run: %s, %v", res.Outcome, err)
	}
	runner.app = goldenCases["sql_payload_marker"].safe
	if res, err := Run(context.Background(), runner, target, poc); err != nil || res.Outcome != NotVerified {
		t.Fatalf("second run against a fixed app: %s, %v", res.Outcome, err)
	}
	if len(runner.looked) != 2 || runner.looked[0] == runner.looked[1] {
		t.Errorf("marker tables %v: want a fresh one per run", runner.looked)
	}
	stored := ""
	reflectPoC := mustBuild(t, loadRequest(t, reflectFixture))
	remember := func(req string, _ map[string]bool) (string, time.Duration) {
		if stored == "" {
			raw, _, _ := strings.Cut(strings.TrimPrefix(req, "GET /search?q="), " ")
			stored = unescape(raw)
		}
		return page(stored), fast
	}
	reflectRunner := newFake(remember)
	for i, want := range []Outcome{Verified, NotVerified} {
		if res, err := Run(context.Background(), reflectRunner, Target{Port: testPort}, reflectPoC); err != nil || res.Outcome != want {
			t.Errorf("reflect run %d: %s, %v; want %s", i+1, res.Outcome, err, want)
		}
	}
}

// TestPathNeedsTheCanary: without a planted canary file a path_payload is
// an error and nothing is sent.
func TestPathNeedsTheCanary(t *testing.T) {
	for _, canary := range []string{"", "short"} {
		runner := newFake(canaryApp(""))
		runner.canary = canary
		if _, err := runOnce(runner, Target{Port: testPort}, mustBuild(t, loadRequest(t, "path_payload_relative"))); !errors.Is(err, ErrRunner) {
			t.Errorf("canary %q: %v, want ErrRunner", canary, err)
		}
		if len(runner.sent) != 0 {
			t.Errorf("canary %q: requests sent", canary)
		}
	}
}
