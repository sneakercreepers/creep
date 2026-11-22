package verify

import (
	"encoding/json"
	"flag"
	"html"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/golden/*.golden")

// goldenCase is one fixture: a vulnerable app the PoC must verify, a safe
// twin it must not, and the oracle it is judged by.
type goldenCase struct {
	vulnerable, safe app
	database         bool
	oracle           string
}

var goldenCases = map[string]goldenCase{
	"http_request_reflect": {
		vulnerable: searchApp(func(s string) string { return s }),
		safe:       searchApp(html.EscapeString),
		oracle:     OracleReflect,
	},
	"http_request_header": {
		vulnerable: welcomeApp(func(s string) string { return s }),
		safe:       welcomeApp(html.EscapeString),
		oracle:     OracleReflect,
	},
	"http_sequence_cookie": {
		vulnerable: cookieApp(func(s string) string { return s }), safe: cookieApp(html.EscapeString), oracle: OracleReflect,
	},
	"http_sequence_bearer": {
		vulnerable: bearerApp(true), safe: bearerApp(false), oracle: OracleReflect,
	},
	"sql_payload_delay": {
		vulnerable: func(req string, _ map[string]bool) (string, time.Duration) {
			if strings.Contains(req, "pg_sleep%283%29") {
				return ok("[]"), 3100 * time.Millisecond
			}
			return ok("[]"), fast
		},
		safe:   func(string, map[string]bool) (string, time.Duration) { return ok("[]"), fast },
		oracle: OracleDelay,
	},
	"sql_payload_marker": {
		vulnerable: func(req string, tables map[string]bool) (string, time.Duration) {
			if m := createdTable.FindStringSubmatch(req); m != nil {
				tables[m[1]] = true
			}
			return status("500 Internal Server Error"), fast
		},
		safe:     func(string, map[string]bool) (string, time.Duration) { return status("400 Bad Request"), fast },
		database: true, oracle: OracleDBMarker,
	},
	"path_payload_relative": {
		vulnerable: canaryApp("=../../../../etc/creep-canary "), safe: canaryApp("never"), oracle: OracleFileMarker,
	},
	"path_payload_encoded": {
		vulnerable: canaryApp("etc%2fcreep-canary"), safe: canaryApp("never"), oracle: OracleFileMarker,
	},
	"path_payload_absolute": {
		vulnerable: canaryApp("f=/etc/creep-canary "), safe: canaryApp("never"), oracle: OracleFileMarker,
	},
}

// searchApp writes the decoded q of GET /search into its HTML through
// escape: as it is when vulnerable, HTML-escaped when safe.
func searchApp(escape func(string) string) app {
	return func(req string, _ map[string]bool) (string, time.Duration) {
		raw, _, _ := strings.Cut(strings.TrimPrefix(req, "GET /search?q="), " ")
		q := unescape(raw)
		return page("<p>results for " + escape(q) + "</p>"), fast
	}
}

// welcomeApp greets the request's User-Agent in its HTML.
func welcomeApp(escape func(string) string) app {
	return func(req string, _ map[string]bool) (string, time.Duration) {
		_, rest, _ := strings.Cut(req, "\r\nUser-Agent: ")
		ua, _, _ := strings.Cut(rest, "\r\n")
		return page("<p>hello " + escape(ua) + "</p>"), fast
	}
}

// cookieApp logs in with a cookie, then shows a posted comment to the
// session that has it.
func cookieApp(escape func(string) string) app {
	return func(req string, _ map[string]bool) (string, time.Duration) {
		switch {
		case strings.HasPrefix(req, "POST /login "):
			return "HTTP/1.1 302 Found\r\nSet-Cookie: session=s3ss10n; Path=/; HttpOnly\r\nSet-Cookie: bad value=x\r\nLocation: /\r\n\r\n", fast
		case !strings.Contains(req, "\r\nCookie: session=s3ss10n\r\n"):
			return status("403 Forbidden"), fast
		}
		_, body, _ := strings.Cut(req, "\r\n\r\n")
		return page("<li>" + escape(unescape(strings.TrimPrefix(body, "text="))) + "</li>"), fast
	}
}

// bearerApp logs in with a bearer token, then shows the profile's bio: as
// it is when vulnerable, escaped when safe.
func bearerApp(vulnerable bool) app {
	return func(req string, _ map[string]bool) (string, time.Duration) {
		switch {
		case strings.HasPrefix(req, "POST /api/login "):
			return ok(`{"access_token":"tok.abc-123","expires":3600}`), fast
		case !strings.Contains(req, "\r\nAuthorization: Bearer tok.abc-123\r\n"):
			return status("401 Unauthorized"), fast
		}
		_, body, _ := strings.Cut(req, "\r\n\r\n")
		var profile struct{ Bio string }
		_ = json.Unmarshal([]byte(body), &profile)
		if !vulnerable {
			profile.Bio = html.EscapeString(profile.Bio)
		}
		return page("<div>" + profile.Bio + "</div>"), fast
	}
}

// canaryApp serves creep's canary file, chunked so its content is split
// across chunks, when the request holds needle.
func canaryApp(needle string) app {
	return func(req string, _ map[string]bool) (string, time.Duration) {
		if !strings.Contains(req, needle) {
			return status("404 Not Found"), fast
		}
		return "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\ncreep-\r\n" +
			strconv.FormatInt(int64(len(testCanary)-6+1), 16) + "\r\n" + testCanary[6:] + "\n\r\n0\r\n\r\n", fast
	}
}

// unescape decodes a URL-encoded query value as an app would: %XX and +.
// verify may not import net/url (make budget), so the tests decode it.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '+':
			b.WriteByte(' ')
		case s[i] == '%' && i+2 < len(s):
			n, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b.WriteByte(byte(n))
			i += 2
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// TestTemplatesGolden is the golden test per template: each fixture
// builds, sends exactly the requests in its .golden file (go test
// ./internal/verify -run TestTemplatesGolden -update rewrites them), is
// verified against its vulnerable app and not against the safe twin, with
// the template's oracle.
func TestTemplatesGolden(t *testing.T) {
	for name, tc := range goldenCases {
		t.Run(name, func(t *testing.T) {
			poc := mustBuild(t, loadRequest(t, name))
			target := Target{Port: testPort, Database: tc.database}
			vuln := newFake(tc.vulnerable)
			res, err := runOnce(vuln, target, poc)
			if err != nil || res.Outcome != Verified || res.Oracle != tc.oracle || res.Template != poc.Template() {
				t.Fatalf("vulnerable app: %+v, %v", res, err)
			}
			checkGolden(t, name, res.Steps)
			safe := newFake(tc.safe)
			if res, err := runOnce(safe, target, poc); err != nil || res.Outcome != NotVerified {
				t.Fatalf("safe app: %s, %v", res.Outcome, err)
			}
		})
	}
}

// checkGolden compares each step's role and request with the .golden
// file: one line per step, the request Go-quoted so line endings survive
// any checkout.
func checkGolden(t *testing.T, name string, steps []Step) {
	t.Helper()
	var b strings.Builder
	for _, s := range steps {
		b.WriteString(s.Role + " " + strconv.Quote(string(s.Request)) + "\n")
	}
	path := filepath.Join("testdata", "golden", name+".golden")
	if *update {
		if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("requests differ from %s:\ngot:\n%s\nwant:\n%s", path, got, want)
	}
}
