package verify

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// keepText is a scrub that finds nothing, as redact.File finds nothing in
// an opaque session: whatever a bundle masks here, it masks on its own.
func keepText(text []byte) (string, error) { return string(text), nil }

// Protection (#25): the session an auth step hands back, and the header
// that sends it, never reach a bundle, though redact.File has no rule for
// them; the PoC still verifies, since masking happens after the runs.
func TestBundleMasksSessions(t *testing.T) {
	tests := []struct {
		fixture string
		app     app
		session string
	}{
		{"http_sequence_cookie", cookieApp(func(s string) string { return s }), "s3ss10n"},
		{"http_sequence_bearer", bearerApp(true), "tok.abc-123"},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			p, rep := repeated(t, tt.app, loadRequest(t, tt.fixture))
			b, err := NewBundle(testMeta(), p, rep, keepText)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := WriteBundle(&out, b); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), tt.session) {
				t.Fatalf("bundle holds the session %q:\n%s", tt.session, out.String())
			}
			if b.Rate != (Rate{5, 5}) || !strings.Contains(out.String(), HeaderMask) {
				t.Errorf("rate %v, or nothing masked:\n%s", b.Rate, out.String())
			}
		})
	}
}

// TestMaskCredentials: every credential header's value is masked in the
// head, CRLF or LF, in any case; a session value of 8 bytes or more is
// masked wherever it appears in the run; a header-like line in a body and
// a Set-Cookie's attributes are left alone.
func TestMaskCredentials(t *testing.T) {
	tests := []struct {
		name          string
		req, resp     string
		gone, kept    []string
		wantReq, want string // exact masked texts, when set
	}{
		{name: "bearer in the body of the auth answer",
			req:  "PUT /p HTTP/1.1\r\nAuthorization: Bearer opaque-token-1\r\n\r\n{}",
			resp: "HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"opaque-token-1\"}",
			gone: []string{"opaque-token-1"}},
		{name: "set-cookie, LF only, lower case",
			req:  "GET / HTTP/1.1\r\n\r\n",
			resp: "HTTP/1.1 302 Found\nset-cookie: sid=cookie-value-2; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT\n\nsid is cookie-value-2 until Wed, 21 Oct 2026 07:28:00 GMT",
			gone: []string{"cookie-value-2"}, kept: []string{"Wed, 21 Oct 2026"}},
		{name: "every cookie of a Cookie header",
			req:  "GET / HTTP/1.1\r\nCookie: a=first-cookie-3; b=\"second-cookie-4\"\r\n\r\nfirst-cookie-3 second-cookie-4",
			gone: []string{"first-cookie-3", "second-cookie-4"}},
		{name: "keys and proxies",
			req:  "GET / HTTP/1.1\r\nX-Api-Key: key-value-5\r\nProxy-Authorization: Basic YWJjOmRlZg==\r\nX-Auth-Token: tok-6\r\n\r\n",
			gone: []string{"key-value-5", "YWJjOmRlZg==", "tok-6"}},
		{name: "short value masked in the head only",
			req:     "GET / HTTP/1.1\r\nCookie: s=abc\r\n\r\nabc",
			wantReq: "GET / HTTP/1.1\r\nCookie: " + HeaderMask + "\r\n\r\nabc"},
		{name: "header-like line in a body",
			resp: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nAuthorization: not-a-header-7\r\n",
			want: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nAuthorization: not-a-header-7\r\n"},
		{name: "no head end",
			resp: "HTTP/1.1 200 OK\r\nSet-Cookie: sid=cut-off-cookie-8",
			gone: []string{"cut-off-cookie-8"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskCredentials([]Step{{Request: []byte(tt.req), Response: []byte(tt.resp)}})[0]
			all := string(got[0]) + "\n" + string(got[1])
			for _, g := range tt.gone {
				if strings.Contains(all, g) {
					t.Errorf("%q kept:\n%s", g, all)
				}
			}
			for _, k := range tt.kept {
				if !strings.Contains(all, k) {
					t.Errorf("%q masked:\n%s", k, all)
				}
			}
			if tt.wantReq != "" && string(got[0]) != tt.wantReq {
				t.Errorf("request %q, want %q", got[0], tt.wantReq)
			}
			if tt.want != "" && string(got[1]) != tt.want {
				t.Errorf("response %q, want %q", got[1], tt.want)
			}
		})
	}
}

// FuzzMaskCredentials: whatever session an app issues, by cookie or by a
// token in its body, no copy of it is left in any step of the run.
func FuzzMaskCredentials(f *testing.F) {
	for _, seed := range []string{"s3ss10n-long", "tok.abc-123", "a-b-c-d-e-f-g-h", "00000000"} {
		f.Add(seed, true)
		f.Add(seed, false)
	}
	f.Fuzz(func(t *testing.T, token string, cookie bool) {
		if len(token) < minCredential || len(token) > 256 || strings.Trim(token, "abcdefghijklmnopqrstuvwxyz0123456789.-_") != "" {
			t.Skip("not a session value an app would issue")
		}
		auth := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"access_token\":\"" + token + "\"}"
		next := "GET /p HTTP/1.1\r\nAuthorization: Bearer " + token + "\r\n\r\n"
		if cookie {
			auth = "HTTP/1.1 302 Found\nSet-Cookie: sid=" + token + "; HttpOnly\n\nwelcome " + token
			next = "GET /p HTTP/1.1\r\nCookie: sid=" + token + "\r\n\r\n"
		}
		steps := []Step{
			{Role: RoleAuth, Request: []byte("POST /login HTTP/1.1\r\n\r\n"), Response: []byte(auth), Elapsed: time.Millisecond},
			{Role: RoleRequest, Request: []byte(next), Response: []byte("HTTP/1.1 200 OK\r\n\r\nhi " + token)},
		}
		for i, m := range maskCredentials(steps) {
			if bytes.Contains(m[0], []byte(token)) || bytes.Contains(m[1], []byte(token)) {
				t.Fatalf("step %d keeps %q:\n%s\n%s", i, token, m[0], m[1])
			}
		}
	})
}
