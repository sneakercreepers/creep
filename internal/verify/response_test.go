package verify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/sandbox"
)

func TestParseResponse(t *testing.T) {
	tests := map[string]struct {
		raw    string
		status int
		body   string
		ok     bool
	}{
		"plain":               {"HTTP/1.1 200 OK\r\nA: b\r\n\r\nhello", 200, "hello", true},
		"no reason":           {"HTTP/1.1 404\r\n\r\n", 404, "", true},
		"HTTP/1.0":            {"HTTP/1.0 302 Found\r\n\r\nx", 302, "x", true},
		"bare LF":             {"HTTP/1.1 200 OK\nA: b\n\nhello", 200, "hello", true},
		"chunked":             {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\n\r\n", 200, "abcde", true},
		"chunked, cut":        {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\nabc", 200, "ff\r\nabc", true},
		"chunked, bad size":   {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n", 200, "zz\r\nabc\r\n0\r\n\r\n", true},
		"chunked not last":    {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n3\r\nabc\r\n0\r\n\r\n", 200, "3\r\nabc\r\n0\r\n\r\n", true},
		"empty":               {"", 0, "", false},
		"no end of header":    {"HTTP/1.1 200 OK\r\nA: b\r\n", 0, "", false},
		"not HTTP":            {"SSH-2.0-OpenSSH\r\n\r\n", 0, "", false},
		"HTTP/2 line":         {"HTTP/2 200\r\n\r\n", 0, "", false},
		"status out of range": {"HTTP/1.1 999 Odd\r\n\r\n", 0, "", false},
		"status not a number": {"HTTP/1.1 2x0 OK\r\n\r\n", 0, "", false},
		"head past the cap":   {"HTTP/1.1 200 OK\r\nA: " + strings.Repeat("a", maxHead) + "\r\n\r\n", 0, "", false},
		"too many headers":    {"HTTP/1.1 200 OK\r\n" + strings.Repeat("A: b\r\n", maxHeaderFields+1) + "\r\n", 0, "", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := parseResponse([]byte(tt.raw))
			if ok != tt.ok || got.status != tt.status || string(got.body) != tt.body {
				t.Errorf("parseResponse = %d %q %t", got.status, got.body, ok)
			}
		})
	}
}

func TestSession(t *testing.T) {
	answer := func(raw string) response {
		r, ok := parseResponse([]byte(raw))
		if !ok {
			t.Fatalf("fixture %q", raw)
		}
		return r
	}
	many := "HTTP/1.1 200 OK\r\n"
	for i := range maxCookies + 2 {
		many += "Set-Cookie: c" + string(rune('a'+i)) + "=1\r\n"
	}
	tests := map[string]struct {
		kind, field, raw string
		want             string
	}{
		"cookies":         {"cookie", "", "HTTP/1.1 200 OK\r\nset-cookie: a=1; Path=/\r\nSet-Cookie: b=2\r\nSet-Cookie: a=3\r\n\r\n", "a=1; b=2"},
		"bad cookies":     {"cookie", "", "HTTP/1.1 200 OK\r\nSet-Cookie: a\r\nSet-Cookie: b c=1\r\nSet-Cookie: d=\"q\"\r\n\r\n", ""},
		"capped cookies":  {"cookie", "", many + "\r\n", "ca=1; cb=1; cc=1; cd=1; ce=1; cf=1; cg=1; ch=1"},
		"long cookie":     {"cookie", "", "HTTP/1.1 200 OK\r\nSet-Cookie: a=" + strings.Repeat("x", maxCookieValue+1) + "\r\n\r\n", ""},
		"bearer":          {"bearer", "token", "HTTP/1.1 200 OK\r\n\r\n{\"token\":\"abc.def\"}", "Bearer abc.def"},
		"bearer missing":  {"bearer", "token", "HTTP/1.1 200 OK\r\n\r\n{\"access\":\"abc\"}", ""},
		"bearer number":   {"bearer", "token", "HTTP/1.1 200 OK\r\n\r\n{\"token\":12}", ""},
		"bearer space":    {"bearer", "token", "HTTP/1.1 200 OK\r\n\r\n{\"token\":\"a b\"}", ""},
		"bearer too long": {"bearer", "token", "HTTP/1.1 200 OK\r\n\r\n{\"token\":\"" + strings.Repeat("a", maxToken+1) + "\"}", ""},
		"bearer not JSON": {"bearer", "token", "HTTP/1.1 200 OK\r\n\r\ntoken=abc", ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h, ok := session(tt.kind, tt.field, answer(tt.raw))
			if ok != (tt.want != "") || h.Value != tt.want {
				t.Errorf("session = %+v, %t; want %q", h, ok, tt.want)
			}
		})
	}
}

// failingRunner answers like a sandbox whose run was aborted, or like one
// that lost a request.
type failingRunner struct {
	err   error
	short bool
}

func (f failingRunner) Exchange(_ context.Context, _ int, requests [][]byte) ([]sandbox.Exchange, error) {
	if f.short {
		return make([]sandbox.Exchange, len(requests)-1), nil
	}
	return nil, f.err
}

func (f failingRunner) DatabaseHasTable(context.Context, string) (bool, error) { return false, f.err }

// TestRunnerErrorsAreErrors: a sandbox error (the canary aborted the run)
// or a runner that lost an answer is an error, never an outcome.
func TestRunnerErrorsAreErrors(t *testing.T) {
	for _, fixture := range []string{statusFixture, "http_sequence_cookie", "sql_payload_delay", "sql_payload_marker", "path_payload_relative"} {
		poc := mustBuild(t, loadRequest(t, fixture))
		target := Target{Port: testPort, Database: true}
		if _, err := Run(context.Background(), failingRunner{err: sandbox.ErrNetworkLeak}, target, poc); !errors.Is(err, sandbox.ErrNetworkLeak) {
			t.Errorf("%s, aborted run: %v", fixture, err)
		}
		if _, err := Run(context.Background(), failingRunner{short: true}, target, poc); !errors.Is(err, ErrRunner) {
			t.Errorf("%s, lost answer: %v", fixture, err)
		}
	}
	lookup := newFake(always(ok("")))
	poc := mustBuild(t, loadRequest(t, "sql_payload_marker"))
	if _, err := Run(context.Background(), &lookupFails{lookup}, Target{Port: testPort, Database: true}, poc); !errors.Is(err, sandbox.ErrDatabase) {
		t.Errorf("failed marker lookup: %v", err)
	}
}

type lookupFails struct{ *fakeRunner }

func (lookupFails) DatabaseHasTable(context.Context, string) (bool, error) {
	return false, sandbox.ErrDatabase
}
