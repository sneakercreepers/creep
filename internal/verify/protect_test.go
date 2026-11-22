package verify

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// mutation breaks one rule of a valid fixture.
type mutation struct {
	fixture string
	change  func(r *Request)
}

func onCall(fixture string, change func(c *Call)) mutation {
	return mutation{fixture, func(r *Request) {
		switch {
		case r.HTTPRequest != nil:
			change(&r.HTTPRequest.Request)
		case r.HTTPSequence != nil:
			change(&r.HTTPSequence.Request)
		case r.SQLPayload != nil:
			change(&r.SQLPayload.Request)
		case r.PathPayload != nil:
			change(&r.PathPayload.Request)
		}
	}}
}

func header(name, value string) func(c *Call) {
	return func(c *Call) { c.Headers = append(c.Headers, Header{Name: name, Value: value}) }
}

func invalidRequests() map[string]mutation {
	m := map[string]mutation{
		"unknown template":         {headerFixture, func(r *Request) { r.Template = "shell_EVIL" }},
		"template in upper case":   {headerFixture, func(r *Request) { r.Template = "HTTP_REQUEST" }},
		"template of other params": {headerFixture, func(r *Request) { r.Template = TemplateSQLPayload }},
		"no parameters":            {headerFixture, func(r *Request) { r.HTTPRequest = nil }},
		"two parameter sets":       {headerFixture, func(r *Request) { r.PathPayload = &PathPayload{} }},
		"method CONNECT":           onCall(headerFixture, func(c *Call) { c.Method = "CONNECT" }),
		"method lower case":        onCall(headerFixture, func(c *Call) { c.Method = "get" }),
		"method with a line":       onCall(headerFixture, func(c *Call) { c.Method = "GET /EVIL HTTP/1.1\r\nHost: evil.example\r\n\r\nGET" }),
		"absolute URL":             onCall(headerFixture, func(c *Call) { c.Path = "http://evil.example/EVIL" }),
		"scheme-relative path":     onCall(headerFixture, func(c *Call) { c.Path = "//evil.example/EVIL" }),
		"no leading slash":         onCall(headerFixture, func(c *Call) { c.Path = "evil.example/EVIL" }),
		"empty path":               onCall(headerFixture, func(c *Call) { c.Path = "" }),
		"space in path":            onCall(headerFixture, func(c *Call) { c.Path = "/a HTTP/1.1\r\nHost: evil.example\r\nX: EVIL" }),
		"line break in path":       onCall(headerFixture, func(c *Call) { c.Path = "/a\nEVIL" }),
		"fragment":                 onCall(headerFixture, func(c *Call) { c.Path = "/a#EVIL" }),
		"backslash":                onCall(headerFixture, func(c *Call) { c.Path = "/\\\\evil.example\\EVIL" }),
		"bad escape":               onCall(headerFixture, func(c *Call) { c.Path = "/%zzEVIL" }),
		"cut escape":               onCall(headerFixture, func(c *Call) { c.Path = "/EVIL%4" }),
		"path too long":            onCall(headerFixture, func(c *Call) { c.Path = "/" + strings.Repeat("a", maxPath) }),
		"Host header":              onCall(headerFixture, header("Host", "evil.example")),
		"host header lower case":   onCall(headerFixture, header("host", "evil.example")),
		"Content-Length header":    onCall(headerFixture, header("Content-Length", "0")),
		"Transfer-Encoding":        onCall(headerFixture, header("Transfer-Encoding", "chunked")),
		"Connection header":        onCall(headerFixture, header("Connection", "keep-alive")),
		"unknown header":           onCall(headerFixture, header("X-EVIL", "1")),
		"X-Forwarded-For":          onCall(headerFixture, header("X-Forwarded-For", "127.0.0.1")),
		"X-Forwarded-Host":         onCall(headerFixture, header("X-Forwarded-Host", "evil.example")),
		"X-Forwarded-Proto":        onCall(headerFixture, header("X-Forwarded-Proto", "https")),
		"Forwarded":                onCall(headerFixture, header("Forwarded", "host=evil.example")),
		"X-Original-URL":           onCall(headerFixture, header("X-Original-URL", "/EVIL")),
		"X-Http-Method-Override":   onCall(headerFixture, header("X-Http-Method-Override", "DELETE")),
		"duplicate header":         onCall(reflectFixture, header("Accept", "*/*")),
		"too many headers": onCall(headerFixture, func(c *Call) {
			for _, h := range allowedHeaders[:maxHeaders+1] {
				c.Headers = append(c.Headers, Header{Name: h, Value: "x"})
			}
		}),
		"header value with a line": onCall(headerFixture, header("Accept", "x\r\nHost: evil.example")),
		"header value with LF":     onCall(headerFixture, header("Accept", "x\nEVIL")),
		"empty header value":       onCall(headerFixture, header("Accept", "")),
		"padded header value":      onCall(headerFixture, header("Accept", " EVIL")),
		"non-ASCII header value":   onCall(headerFixture, header("Accept", "EVILé")),
		"header value too long":    onCall(headerFixture, header("Accept", strings.Repeat("a", maxHeaderValue+1))),
		"body without type":        onCall(headerFixture, func(c *Call) { c.Method, c.Body = "POST", "EVIL" }),
		"unknown content type":     onCall(headerFixture, func(c *Call) { c.Method, c.ContentType, c.Body = "POST", "application/x-sh", "EVIL" }),
		"type without body":        onCall(headerFixture, func(c *Call) { c.Method, c.ContentType = "POST", contentText }),
		"GET with body":            onCall(headerFixture, func(c *Call) { c.ContentType, c.Body = contentText, "EVIL" }),
		"invalid JSON":             onCall(headerFixture, func(c *Call) { c.Method, c.ContentType, c.Body = "POST", contentJSON, "{EVIL" }),
		"form with space":          onCall(headerFixture, func(c *Call) { c.Method, c.ContentType, c.Body = "POST", contentForm, "a=EVIL b" }),
		"body too long":            onCall(headerFixture, func(c *Call) { c.Method, c.ContentType, c.Body = "POST", contentText, strings.Repeat("a", maxBody+1) }),
		"body with NUL":            onCall(headerFixture, func(c *Call) { c.Method, c.ContentType, c.Body = "POST", contentText, "EVIL\x00" }),
		"body not UTF-8":           onCall(headerFixture, func(c *Call) { c.Method, c.ContentType, c.Body = "POST", contentText, "EVIL\xff" }),
		"payload in http_request":  onCall(headerFixture, func(c *Call) { c.Path = "/a?b=" + PayloadPlaceholder }),
	}
	for name, mu := range oracleMutations() {
		m[name] = mu
	}
	for name, mu := range templateMutations() {
		m[name] = mu
	}
	return m
}

func oracleMutations() map[string]mutation {
	return map[string]mutation{
		"unknown oracle":    {headerFixture, func(r *Request) { r.HTTPRequest.Oracle.Kind = "always" }},
		"status oracle":     {headerFixture, func(r *Request) { r.HTTPRequest.Oracle.Kind = "status" }},
		"no oracle kind":    {headerFixture, func(r *Request) { r.HTTPRequest.Oracle.Kind = "" }},
		"status 99":         {headerFixture, func(r *Request) { r.HTTPRequest.Oracle.Status = 99 }},
		"status 600":        {headerFixture, func(r *Request) { r.HTTPRequest.Oracle.Status = 600 }},
		"negative status":   {headerFixture, func(r *Request) { r.HTTPRequest.Oracle.Status = -1 }},
		"reflect, no nonce": onCall(reflectFixture, func(c *Call) { c.Path = "/search" }),
		"five nonces":       onCall(reflectFixture, func(c *Call) { c.Path = "/s?" + strings.Repeat(NoncePlaceholder, 5) }),
		"sequence status oracle": {"http_sequence_cookie", func(r *Request) {
			r.HTTPSequence.Oracle = Oracle{Kind: "status", Status: 200}
		}},
	}
}

func templateMutations() map[string]mutation {
	seq := func(change func(s *HTTPSequence)) mutation {
		return mutation{"http_sequence_cookie", func(r *Request) { change(r.HTTPSequence) }}
	}
	sql := func(change func(s *SQLPayload)) mutation {
		return mutation{"sql_payload_delay", func(r *Request) { change(r.SQLPayload) }}
	}
	path := func(change func(s *PathPayload)) mutation {
		return mutation{"path_payload_relative", func(r *Request) { change(r.PathPayload) }}
	}
	return map[string]mutation{
		"unknown session":            seq(func(s *HTTPSequence) { s.Session = "basic" }),
		"cookie with a token field":  seq(func(s *HTTPSequence) { s.TokenField = "token" }),
		"cookie and a Cookie header": seq(func(s *HTTPSequence) { s.Request.Headers = append(s.Request.Headers, Header{"Cookie", "a=b"}) }),
		"bearer without a field":     seq(func(s *HTTPSequence) { s.Session = "bearer" }),
		"bearer odd field":           seq(func(s *HTTPSequence) { s.Session, s.TokenField = "bearer", "a-EVIL" }),
		"bearer and Authorization": seq(func(s *HTTPSequence) {
			s.Session, s.TokenField = "bearer", "token"
			s.Request.Headers = append(s.Request.Headers, Header{"Authorization", "Basic EVIL"})
		}),
		"nonce in auth":            seq(func(s *HTTPSequence) { s.Auth.Path = "/login?" + NoncePlaceholder }),
		"payload in auth":          seq(func(s *HTTPSequence) { s.Auth.Path = "/login?" + PayloadPlaceholder }),
		"bad auth path":            seq(func(s *HTTPSequence) { s.Auth.Path = "//evil.example/EVIL" }),
		"no payload placeholder":   sql(func(s *SQLPayload) { s.Request.Path = "/items" }),
		"two payload placeholders": sql(func(s *SQLPayload) { s.Request.Path += "&b=" + PayloadPlaceholder }),
		"payload in a header": sql(func(s *SQLPayload) {
			s.Request.Path = "/items"
			s.Request.Headers = []Header{{"Cookie", "id=" + PayloadPlaceholder}}
		}),
		"nonce with payload":    sql(func(s *SQLPayload) { s.Request.Path += "&n=" + NoncePlaceholder }),
		"unknown SQL context":   sql(func(s *SQLPayload) { s.Context = "EVIL" }),
		"unknown SQL technique": sql(func(s *SQLPayload) { s.Technique = "drop_table" }),
		"absolute with depth":   path(func(s *PathPayload) { s.Style, s.Depth = "absolute", 3 }),
		"relative depth 0":      path(func(s *PathPayload) { s.Depth = 0 }),
		"relative too deep":     path(func(s *PathPayload) { s.Depth = maxDepth + 1 }),
		"unknown style":         path(func(s *PathPayload) { s.Style = "../EVIL" }),
	}
}

// TestInvalidPoCRejectedBeforeRun is the protection test for the closed
// schema: an unknown template, parameters of another template, and every
// broken rule of a method, path, header, body, oracle, session, payload
// placement or style is refused by Build with ErrInvalid, in a message
// that never quotes the model's text; Run refuses a PoC Build did not
// make, and the runner is never called.
func TestInvalidPoCRejectedBeforeRun(t *testing.T) {
	for name, mu := range invalidRequests() {
		t.Run(name, func(t *testing.T) {
			req := loadRequest(t, mu.fixture)
			if _, err := Build(req); err != nil {
				t.Fatalf("the fixture itself fails: %v", err)
			}
			mu.change(&req)
			_, err := Build(req)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Build = %v, want ErrInvalid", err)
			}
			if strings.Contains(err.Error(), "EVIL") || strings.Contains(err.Error(), "evil.example") {
				t.Errorf("the message quotes the model's text: %v", err)
			}
		})
	}
	runner := newFake(always(ok("")))
	if _, err := Run(context.Background(), runner, Target{Port: testPort}, PoC{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("Run of a zero PoC: %v", err)
	}
	poc := mustBuild(t, loadRequest(t, headerFixture))
	for _, port := range []int{0, -1, 65536} {
		if _, err := Run(context.Background(), runner, Target{Port: port}, poc); !errors.Is(err, ErrInvalid) {
			t.Errorf("Run on port %d: %v", port, err)
		}
	}
	if len(runner.sent) != 0 {
		t.Errorf("the runner was called: %q", runner.sent)
	}
}

// TestBuildCopiesTheRequest: changing the model's Request after Build
// changes nothing that runs.
func TestBuildCopiesTheRequest(t *testing.T) {
	req := loadRequest(t, reflectFixture)
	poc := mustBuild(t, req)
	req.HTTPRequest.Request.Headers[0] = Header{Name: "Host", Value: "evil.example"}
	req.HTTPRequest.Request.Path = "//evil.example/"
	runner := newFake(always(ok("")))
	if _, err := Run(context.Background(), runner, Target{Port: testPort}, poc); err != nil {
		t.Fatal(err)
	}
	if got := string(runner.requests()[0]); strings.Contains(got, "evil.example") || !strings.Contains(got, "\r\nHost: app:8080\r\n") {
		t.Errorf("a change after Build reached the request: %q", got)
	}
}
