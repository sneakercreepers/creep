package verify

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
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
		poc, err := Build(req)
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
