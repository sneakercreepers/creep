package verify

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// creepHeaders are the header names creep writes itself.
var creepHeaders = []string{"Host", "Content-Type", "Content-Length", "Connection", "Cookie", "Authorization"}

// requestProblems checks one raw request against what a model may
// control: an origin-form request line, exactly one Host, the app's, only
// allowed header names, every line ended by CRLF, and a Content-Length
// that matches the body.
func requestProblems(raw string, port int) []string {
	head, body, found := strings.Cut(raw, "\r\n\r\n")
	if !found {
		return []string{"no end of header"}
	}
	lines := strings.Split(head, "\r\n")
	var problems []string
	if f := strings.Split(lines[0], " "); len(f) != 3 || !slices.Contains(methods, f[0]) || !strings.HasPrefix(f[1], "/") ||
		strings.HasPrefix(f[1], "//") || f[2] != "HTTP/1.1" {
		problems = append(problems, "request line "+strconv.Quote(lines[0]))
	}
	hosts, length := 0, -1
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ": ")
		switch {
		case !ok || strings.ContainsAny(line, "\r\n"):
			problems = append(problems, "header line "+strconv.Quote(line))
		case name == "Host":
			hosts++
			if value != "app:"+strconv.Itoa(port) {
				problems = append(problems, "host "+strconv.Quote(value))
			}
		case name == "Content-Length":
			length, _ = strconv.Atoi(value)
		case !slices.Contains(allowedHeaders, name) && !slices.Contains(creepHeaders, name):
			problems = append(problems, "header "+strconv.Quote(name))
		}
	}
	if hosts != 1 {
		problems = append(problems, fmt.Sprintf("%d Host headers", hosts))
	}
	if length != len(body) && (length != -1 || body != "") {
		problems = append(problems, fmt.Sprintf("Content-Length %d for %d bytes", length, len(body)))
	}
	return problems
}

// TestModelCannotPickHost is the protection test for where a PoC goes:
// every request of every fixture, against its vulnerable and its safe
// app, is origin form with one Host, the app on the target's port; the
// runner is only ever given that port; and a session the app hands back
// with line breaks or spaces is no session, so it never adds a header.
func TestModelCannotPickHost(t *testing.T) {
	for name, tc := range goldenCases {
		for _, a := range []app{tc.vulnerable, tc.safe} {
			for _, port := range []int{testPort, 1, 65535} {
				runner := newFake(a)
				if _, err := Run(context.Background(), runner, Target{Port: port, Database: tc.database}, mustBuild(t, loadRequest(t, name))); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				for _, r := range runner.requests() {
					if p := requestProblems(string(r), port); len(p) > 0 {
						t.Errorf("%s: %q: %v", name, r, p)
					}
				}
				if slices.ContainsFunc(runner.ports, func(p int) bool { return p != port }) {
					t.Errorf("%s: runner ports %v, want only %d", name, runner.ports, port)
				}
			}
		}
	}
	checkHostileSessions(t)
}

func checkHostileSessions(t *testing.T) {
	t.Helper()
	answers := map[string]string{
		"http_sequence_cookie": "HTTP/1.1 200 OK\r\nSet-Cookie: s=a\"b\r\nSet-Cookie: s=a b\r\nSet-Cookie: s=a,b\r\nSet-Cookie: =x\r\n\r\n",
		"http_sequence_bearer": ok(`{"access_token":"tok\r\nHost: evil.example"}`),
	}
	for name, answer := range answers {
		runner := newFake(always(answer))
		res, err := Run(context.Background(), runner, Target{Port: testPort}, mustBuild(t, loadRequest(t, name)))
		if err != nil || res.Outcome != AuthFailed || len(runner.requests()) != 1 {
			t.Errorf("%s with a hostile session: %s, %v, %d requests", name, res.Outcome, err, len(runner.requests()))
		}
	}
}

// FuzzBuiltRequestStaysOnApp: whatever path, header value and body a model
// sends, a request Build accepts is rendered with the app as its only
// host, its request line in origin form and every header on its own line.
func FuzzBuiltRequestStaysOnApp(f *testing.F) {
	f.Add("/a?b="+NoncePlaceholder, "text/html", `{"a":"`+NoncePlaceholder+`"}`)
	f.Add("//evil.example/"+NoncePlaceholder, "x", "{}")
	f.Add("/"+NoncePlaceholder, "x\r\nHost: evil.example", "{}")
	f.Add("/a HTTP/1.1\r\nHost: evil.example\r\n\r\nGET /", "x", "{}")
	f.Add("http://evil.example/", "é", "\x00")
	f.Fuzz(func(t *testing.T, path, value, body string) {
		req := Request{Template: TemplateHTTPRequest, HTTPRequest: &HTTPRequest{
			Request: Call{Method: "POST", Path: path, Headers: []Header{{Name: "Accept", Value: value}}, ContentType: contentJSON, Body: body},
			Oracle:  Oracle{Kind: OracleReflect},
		}}
		poc, err := build(req, testNonce)
		if err != nil {
			return
		}
		runner := newFake(always(ok("")))
		if _, err := Run(context.Background(), runner, Target{Port: testPort}, poc); err != nil {
			t.Fatal(err)
		}
		if p := requestProblems(string(runner.requests()[0]), testPort); len(p) > 0 {
			t.Fatalf("%q: %v", runner.requests()[0], p)
		}
	})
}

// TestOraclesCannotBeFaked is the protection test for the oracles: an
// app (or a model's choice of request) that always looks vulnerable is
// not verified. A reflection must carry this PoC's nonce, not the
// placeholder or another nonce; a delay must exceed the baseline's; the
// file marker must be missing from the baseline; the database marker is
// creep's table, not one the app names; no database or no answer is
// never verified.
func TestOraclesCannotBeFaked(t *testing.T) {
	slow := func(string, map[string]bool) (string, time.Duration) { return ok("[]"), 3100 * time.Millisecond }
	otherTable := func(_ string, tables map[string]bool) (string, time.Duration) {
		tables["creep_ffffffffffffffffffffffff"], tables["items"] = true, true
		return ok(""), fast
	}
	passwd := passwdApp("")
	silentBaseline := func(req string, tables map[string]bool) (string, time.Duration) {
		if strings.Contains(req, baselineFile) {
			return "", fast
		}
		return passwd(req, tables)
	}
	tests := map[string]struct {
		fixture string
		app     app
		target  Target
		want    Outcome
	}{
		"placeholder echoed":    {reflectFixture, always(ok(NoncePlaceholder)), Target{Port: testPort}, NotVerified},
		"another nonce":         {reflectFixture, always(ok("creepffffffffffffffffffffffff")), Target{Port: testPort}, NotVerified},
		"nonce only in headers": {reflectFixture, always("HTTP/1.1 200 OK\r\nX-Echo: " + testNonce + "\r\n\r\n"), Target{Port: testPort}, NotVerified},
		"slow on every request": {"sql_payload_delay", slow, Target{Port: testPort}, NotVerified},
		"passwd everywhere":     {"path_payload_relative", passwd, Target{Port: testPort}, NotVerified},
		"another table":         {"sql_payload_marker", otherTable, Target{Port: testPort, Database: true}, NotVerified},
		"no database":           {"sql_payload_marker", otherTable, Target{Port: testPort}, NoDatabase},
		"empty answer":          {statusFixture, always(""), Target{Port: testPort}, NoResponse},
		"not HTTP":              {statusFixture, always("SSH-2.0-OpenSSH\r\n\r\n"), Target{Port: testPort}, NoResponse},
		"no baseline answer":    {"path_payload_relative", silentBaseline, Target{Port: testPort}, NoResponse},
		"auth refused":          {"http_sequence_cookie", always("HTTP/1.1 401 Unauthorized\r\nSet-Cookie: s=1\r\n\r\n"), Target{Port: testPort}, AuthFailed},
		"auth without session":  {"http_sequence_cookie", always(ok("")), Target{Port: testPort}, AuthFailed},
		"auth not HTTP":         {"http_sequence_bearer", always("garbage"), Target{Port: testPort}, NoResponse},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			runner := newFake(tt.app)
			res, err := Run(context.Background(), runner, tt.target, mustBuild(t, loadRequest(t, tt.fixture)))
			if err != nil || res.Outcome != tt.want {
				t.Fatalf("Run = %s, %v; want %s", res.Outcome, err, tt.want)
			}
			if tt.want == NoDatabase && len(runner.sent) != 0 {
				t.Errorf("a marker payload was sent with no database")
			}
			for _, table := range runner.looked {
				if table != "creep_"+testNonce[len("creep"):] {
					t.Errorf("looked up %s, not creep's marker", table)
				}
			}
		})
	}
}
