package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

// echoApp is a test app built offline from the pinned BusyBox: httpd
// serves a CGI script that reflects its query string, one that answers
// after three seconds and one that reads the canary file StartApp planted.
func echoApp() Repo {
	return (&memRepo{files: map[string]string{
		"Dockerfile": "FROM " + CanaryImage + "\nCOPY www /www\nRUN chmod -R a+rx /www\n" +
			"CMD [\"httpd\", \"-f\", \"-p\", \"8080\", \"-h\", \"/www\"]\n",
		"www/cgi-bin/echo":   "#!/bin/sh\necho 'Content-Type: text/plain'\necho\necho \"q=$QUERY_STRING\"\n",
		"www/cgi-bin/slow":   "#!/bin/sh\nsleep 3\necho 'Content-Type: text/plain'\necho\necho slow\n",
		"www/cgi-bin/canary": "#!/bin/sh\necho 'Content-Type: text/plain'\necho\ncat " + AppCanaryFile + "\n",
	}}).repo()
}

func get(path string) []byte {
	return []byte("GET " + path + " HTTP/1.1\r\nHost: app:8080\r\nConnection: close\r\n\r\n")
}

// TestRealRunnerReachesTheApp sends requests from the runner on a real
// engine: the app answers each in order, a reflected value comes back, a
// slow answer is timed inside the runner, and a port nothing listens on
// gives an empty response, not an error. The database lookup sees a table
// a migration created and not one it did not.
func TestRealRunnerReachesTheApp(t *testing.T) {
	eachRuntime(t, func(t *testing.T, st Status) {
		pullPinned(t, st)
		s := openReal(t, st)
		ctx := context.Background()
		app, err := s.Build(ctx, echoApp())
		if err != nil || !app.Built() {
			t.Fatalf("Build = %+v, %v", app, err)
		}
		if err := s.StartApp(ctx, app); err != nil {
			t.Fatal(err)
		}
		got, err := s.Exchange(ctx, 8080, [][]byte{get("/cgi-bin/echo?creep0nonce"), get("/cgi-bin/slow")})
		if err != nil || len(got) != 2 {
			t.Fatalf("Exchange = %+v, %v", got, err)
		}
		if r := string(got[0].Response); !strings.HasPrefix(r, "HTTP/1.1 200") || !strings.Contains(r, "q=creep0nonce") || got[0].Elapsed > 2*time.Second {
			t.Errorf("echo: %q in %s", r, got[0].Elapsed)
		}
		if r := string(got[1].Response); !strings.Contains(r, "slow") || got[1].Elapsed < 2500*time.Millisecond {
			t.Errorf("slow: %q in %s", r, got[1].Elapsed)
		}
		checkCanaryRead(t, s)
		closed, err := s.Exchange(ctx, 9, [][]byte{get("/")})
		if err != nil || len(closed) != 1 || len(closed[0].Response) != 0 {
			t.Errorf("closed port: %+v, %v", closed, err)
		}
		checkMarkerLookup(t, s)
	})
}

// checkCanaryRead: the app's user can read the planted canary file, and
// its content is the sandbox's.
func checkCanaryRead(t *testing.T, s *Sandbox) {
	t.Helper()
	got, err := s.Exchange(context.Background(), 8080, [][]byte{get("/cgi-bin/canary")})
	if err != nil || len(got) != 1 || len(s.AppCanary()) < 16 || !strings.Contains(string(got[0].Response), s.AppCanary()) {
		t.Errorf("canary read: %+v, %v", got, err)
	}
}

func checkMarkerLookup(t *testing.T, s *Sandbox) {
	t.Helper()
	const made, absent = "creep_0123456789abcdef", "creep_fedcba9876543210"
	ctx := context.Background()
	if _, err := s.StartDatabase(ctx, []Migration{{Path: "migrations/1.sql", SQL: []byte("CREATE TABLE " + made + " ();")}}); err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]bool{made: true, absent: false} {
		if got, err := s.DatabaseHasTable(ctx, table); err != nil || got != want {
			t.Errorf("DatabaseHasTable(%s) = %t, %v; want %t", table, got, err, want)
		}
	}
}
