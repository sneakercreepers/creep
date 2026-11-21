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

const reflectFixture, statusFixture = "http_request_reflect", "http_request_status"

func invalidRequests() map[string]mutation {
	m := map[string]mutation{
		"unknown template":         {statusFixture, func(r *Request) { r.Template = "shell_EVIL" }},
		"template in upper case":   {statusFixture, func(r *Request) { r.Template = "HTTP_REQUEST" }},
		"template of other params": {statusFixture, func(r *Request) { r.Template = TemplateSQLPayload }},
		"no parameters":            {statusFixture, func(r *Request) { r.HTTPRequest = nil }},
		"two parameter sets":       {statusFixture, func(r *Request) { r.PathPayload = &PathPayload{} }},
		"method CONNECT":           onCall(statusFixture, func(c *Call) { c.Method = "CONNECT" }),
		"method lower case":        onCall(statusFixture, func(c *Call) { c.Method = "get" }),
		"method with a line":       onCall(statusFixture, func(c *Call) { c.Method = "GET /EVIL HTTP/1.1\r\nHost: evil.example\r\n\r\nGET" }),
		"absolute URL":             onCall(statusFixture, func(c *Call) { c.Path = "http://evil.example/EVIL" }),
		"scheme-relative path":     onCall(statusFixture, func(c *Call) { c.Path = "//evil.example/EVIL" }),
		"no leading slash":         onCall(statusFixture, func(c *Call) { c.Path = "evil.example/EVIL" }),
		"empty path":               onCall(statusFixture, func(c *Call) { c.Path = "" }),
		"space in path":            onCall(statusFixture, func(c *Call) { c.Path = "/a HTTP/1.1\r\nHost: evil.example\r\nX: EVIL" }),
		"line break in path":       onCall(statusFixture, func(c *Call) { c.Path = "/a\nEVIL" }),
		"fragment":                 onCall(statusFixture, func(c *Call) { c.Path = "/a#EVIL" }),
		"backslash":                onCall(statusFixture, func(c *Call) { c.Path = "/\\\\evil.example\\EVIL" }),
		"bad escape":               onCall(statusFixture, func(c *Call) { c.Path = "/%zzEVIL" }),
		"cut escape":               onCall(statusFixture, func(c *Call) { c.Path = "/EVIL%4" }),
		"path too long":            onCall(statusFixture, func(c *Call) { c.Path = "/" + strings.Repeat("a", maxPath) }),
		"Host header":              onCall(statusFixture, header("Host", "evil.example")),
		"host header lower case":   onCall(statusFixture, header("host", "evil.example")),
		"Content-Length header":    onCall(statusFixture, header("Content-Length", "0")),
		"Transfer-Encoding":        onCall(statusFixture, header("Transfer-Encoding", "chunked")),
		"Connection header":        onCall(statusFixture, header("Connection", "keep-alive")),
		"unknown header":           onCall(statusFixture, header("X-EVIL", "1")),
		"duplicate header":         onCall(reflectFixture, header("Accept", "*/*")),
		"too many headers": onCall(statusFixture, func(c *Call) {
			for _, h := range allowedHeaders[:maxHeaders+1] {
				c.Headers = append(c.Headers, Header{Name: h, Value: "x"})
			}
		}),
		"header value with a line": onCall(statusFixture, header("Accept", "x\r\nHost: evil.example")),
		"header value with LF":     onCall(statusFixture, header("Accept", "x\nEVIL")),
		"empty header value":       onCall(statusFixture, header("Accept", "")),
		"padded header value":      onCall(statusFixture, header("Accept", " EVIL")),
		"non-ASCII header value":   onCall(statusFixture, header("Accept", "EVILé")),
		"header value too long":    onCall(statusFixture, header("Accept", strings.Repeat("a", maxHeaderValue+1))),
		"body without type":        onCall(statusFixture, func(c *Call) { c.Method, c.Body = "POST", "EVIL" }),
		"unknown content type":     onCall(statusFixture, func(c *Call) { c.Method, c.ContentType, c.Body = "POST", "application/x-sh", "EVIL" }),
		"type without body":        onCall(statusFixture, func(c *Call) { c.Method, c.ContentType = "POST", contentText }),
		"GET with body":            onCall(statusFixture, func(c *Call) { c.ContentType, c.Body = contentText, "EVIL" }),
		"invalid JSON":             onCall(statusFixture, func(c *Call) { c.Method, c.ContentType, c.Body = "POST", contentJSON, "{EVIL" }),
		"form with space":          onCall(statusFixture, func(c *Call) { c.Method, c.ContentType, c.Body = "POST", contentForm, "a=EVIL b" }),
		"body too long":            onCall(statusFixture, func(c *Call) { c.Method, c.ContentType, c.Body = "POST", contentText, strings.Repeat("a", maxBody+1) }),
		"body with NUL":            onCall(statusFixture, func(c *Call) { c.Method, c.ContentType, c.Body = "POST", contentText, "EVIL\x00" }),
		"body not UTF-8":           onCall(statusFixture, func(c *Call) { c.Method, c.ContentType, c.Body = "POST", contentText, "EVIL\xff" }),
		"payload in http_request":  onCall(statusFixture, func(c *Call) { c.Path = "/a?b=" + PayloadPlaceholder }),
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
		"unknown oracle":     {statusFixture, func(r *Request) { r.HTTPRequest.Oracle.Kind = "always" }},
		"status 0":           {statusFixture, func(r *Request) { r.HTTPRequest.Oracle.Status = 0 }},
		"status 600":         {statusFixture, func(r *Request) { r.HTTPRequest.Oracle.Status = 600 }},
		"status with nonce":  onCall(statusFixture, func(c *Call) { c.Path = "/a?b=" + NoncePlaceholder }),
		"reflect, no nonce":  onCall(reflectFixture, func(c *Call) { c.Path = "/search" }),
		"reflect and status": {reflectFixture, func(r *Request) { r.HTTPRequest.Oracle.Status = 200 }},
		"five nonces":        onCall(reflectFixture, func(c *Call) { c.Path = "/s?" + strings.Repeat(NoncePlaceholder, 5) }),
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
			if _, err := build(req, testNonce); err != nil {
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
	poc := mustBuild(t, loadRequest(t, statusFixture))
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
	if got := string(runner.requests()[0]); strings.Contains(got, "evil.example") {
		t.Errorf("a change after Build reached the request: %q", got)
	}
}
