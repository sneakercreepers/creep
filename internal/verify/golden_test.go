package verify

import (
	"context"
	"flag"
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
		vulnerable: func(req string, _ map[string]bool) (string, time.Duration) {
			q, _, _ := strings.Cut(strings.TrimPrefix(req, "GET /search?q="), " ")
			return ok("<p>results for " + q + "</p>"), fast
		},
		safe: func(string, map[string]bool) (string, time.Duration) {
			return ok("<p>results for your search</p>"), fast
		},
		oracle: OracleReflect,
	},
	"http_request_status": {
		vulnerable: func(string, map[string]bool) (string, time.Duration) { return ok("id,email\n"), fast },
		safe:       func(string, map[string]bool) (string, time.Duration) { return status("401 Unauthorized"), fast },
		oracle:     OracleStatus,
	},
	"http_sequence_cookie": {
		vulnerable: cookieApp(true), safe: cookieApp(false), oracle: OracleStatus,
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
		vulnerable: passwdApp("etc/passwd"), safe: passwdApp("never"), oracle: OracleFileMarker,
	},
	"path_payload_encoded": {
		vulnerable: passwdApp("etc%2fpasswd"), safe: passwdApp("never"), oracle: OracleFileMarker,
	},
}

func cookieApp(vulnerable bool) app {
	return func(req string, _ map[string]bool) (string, time.Duration) {
		switch {
		case strings.HasPrefix(req, "POST /login "):
			return "HTTP/1.1 302 Found\r\nSet-Cookie: session=s3ss10n; Path=/; HttpOnly\r\nSet-Cookie: bad value=x\r\nLocation: /\r\n\r\n", fast
		case strings.Contains(req, "\r\nCookie: session=s3ss10n\r\n") && vulnerable:
			return ok(`{"order":2,"owner":"someone else"}`), fast
		}
		return status("403 Forbidden"), fast
	}
}

func bearerApp(vulnerable bool) app {
	return func(req string, _ map[string]bool) (string, time.Duration) {
		switch {
		case strings.HasPrefix(req, "POST /api/login "):
			return ok(`{"access_token":"tok.abc-123","expires":3600}`), fast
		case !strings.Contains(req, "\r\nAuthorization: Bearer tok.abc-123\r\n"):
			return status("401 Unauthorized"), fast
		case vulnerable:
			_, body, _ := strings.Cut(req, "\r\n\r\n")
			return ok("<div>" + body + "</div>"), fast
		}
		return ok(`{"ok":true}`), fast
	}
}

// passwdApp serves /etc/passwd, chunked so the marker is split across
// chunks, when the request holds needle.
func passwdApp(needle string) app {
	return func(req string, _ map[string]bool) (string, time.Duration) {
		if !strings.Contains(req, needle) {
			return status("404 Not Found"), fast
		}
		return "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nroot:\r\n1a\r\nx:0:0:root:/root:/bin/sh\n\r\n0\r\n\r\n", fast
	}
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
			res, err := Run(context.Background(), vuln, target, poc)
			if err != nil || res.Outcome != Verified || res.Oracle != tc.oracle || res.Template != poc.Template() {
				t.Fatalf("vulnerable app: %+v, %v", res, err)
			}
			checkGolden(t, name, res.Steps)
			safe := newFake(tc.safe)
			if res, err := Run(context.Background(), safe, target, poc); err != nil || res.Outcome != NotVerified {
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
