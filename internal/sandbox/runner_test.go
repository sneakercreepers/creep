package sandbox

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// isRunnerRun tells the runner's run from the canary's: same image, but
// only the runner mounts request files.
func isRunnerRun(args []string) bool {
	return slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, ",target="+requestDir+"/r") })
}

// fakeRunnerAnswer is a runner's output with an empty response for each
// mounted request.
func fakeRunnerAnswer(args []string) []byte {
	var b strings.Builder
	n := 0
	for _, a := range args {
		if strings.Contains(a, ",target="+requestDir+"/r") {
			n++
			b.WriteString("r" + strconv.Itoa(n) + " 100.00 100.25 0\n")
		}
	}
	return []byte(b.String())
}

var ncTarget = regexp.MustCompile(`nc (?:-z -w 2 )?(\S+) (\S+)`)

// hostileRequest is what a model might try to smuggle into a command
// line: flags, shell syntax, line breaks.
const hostileRequest = "GET / HTTP/1.1\r\nHost: app:8080\r\n\r\n--privileged -v /:/host $(reboot) `id`; rm -rf / && nc evil.example 443\n"

// startedApp is a sandbox whose app runs, on rec.
func startedApp(t *testing.T, rec *recorder) *Sandbox {
	t.Helper()
	s := testSandbox(t, rec)
	app, err := s.Build(context.Background(), dockerfileRepo(plainDockerfile))
	if err != nil || !app.Built() {
		t.Fatalf("Build = %+v, %v", app, err)
	}
	if err := s.StartApp(context.Background(), app); err != nil {
		t.Fatalf("StartApp: %v", err)
	}
	return s
}

// TestExchangeRunsOnlyInRunner is the protection test for where PoC
// requests run: only in one hardened runner container on the run network,
// after the canary, from the pinned image, with the request bytes in
// read-only mounted files and never on a command line; the script names
// only the app and creep's port. Nothing runs without a started app, with
// a refused bound, or after the canary leaked.
func TestExchangeRunsOnlyInRunner(t *testing.T) {
	rec := withBuilds(networkRecorder(goodCanary, 0), 0)
	if _, err := testSandbox(t, rec).Exchange(context.Background(), 8080, [][]byte{[]byte(hostileRequest)}); !errors.Is(err, ErrSpec) {
		t.Fatalf("Exchange without an app: %v", err)
	}
	if runs := rec.to("run"); len(runs) != 0 {
		t.Fatalf("Exchange without an app ran %q", runs)
	}
	rec = withBuilds(networkRecorder(goodCanary, 0), 0)
	s := startedApp(t, rec)
	before := len(rec.to("run"))
	got, err := s.Exchange(context.Background(), 8080, [][]byte{[]byte(hostileRequest), []byte("GET /2 HTTP/1.1\r\n\r\n")})
	if err != nil || len(got) != 2 || got[0].Elapsed != 250*time.Millisecond {
		t.Fatalf("Exchange = %+v, %v", got, err)
	}
	runs := rec.to("run")[before:]
	if len(runs) != 2 || isRunnerRun(runs[0]) || !strings.Contains(strings.Join(runs[0], " "), "canary-") || !isRunnerRun(runs[1]) {
		t.Fatalf("runs %q: want the canary, then the runner", runs)
	}
	checkRunnerArgv(t, runs[1])
	for _, argv := range rec.calls {
		for _, a := range argv {
			if strings.Contains(a, "privileged -v") || strings.Contains(a, "reboot") || strings.Contains(a, "evil.example") {
				t.Errorf("request bytes reached a command line: %q", argv)
			}
		}
	}
	checkExchangeRefusals(t)
}

func checkRunnerArgv(t *testing.T, argv []string) {
	t.Helper()
	if p := hardeningProblems(argv); len(p) > 0 {
		t.Errorf("runner %q: %v", argv, p)
	}
	img := slices.Index(argv, RunnerImage)
	if img < 0 || !slices.Contains(argv, "--network=creep-"+testRunID) || !slices.Equal(argv[img+1:img+3], []string{"sh", "-c"}) || len(argv) != img+4 {
		t.Fatalf("runner %q: want the pinned image, the run network and one fixed script", argv)
	}
	// Every connection the script opens goes to the app on creep's port:
	// the readiness check and one per request.
	targets := ncTarget.FindAllStringSubmatch(argv[img+3], -1)
	if len(targets) != 3 || strings.Count(argv[img+3], "nc ") != 3 {
		t.Errorf("runner script %q: %d connections, want 3", argv[img+3], len(targets))
	}
	for _, m := range targets {
		if m[1] != "app" || m[2] != "8080" {
			t.Errorf("runner connects to %s %s", m[1], m[2])
		}
	}
	mounts := 0
	for _, a := range argv[:img] {
		if strings.HasPrefix(a, "--mount=") {
			mounts++
			if !strings.HasSuffix(a, ",readonly") || !strings.Contains(a, ",target="+requestDir+"/r") {
				t.Errorf("runner mount %q", a)
			}
		}
	}
	if mounts != 2 {
		t.Errorf("%d runner mounts, want one per request", mounts)
	}
}

func checkExchangeRefusals(t *testing.T) {
	t.Helper()
	one := [][]byte{[]byte("GET / HTTP/1.1\r\n\r\n")}
	tests := map[string]struct {
		port     int
		requests [][]byte
	}{
		"port 0":          {0, one},
		"port too high":   {65536, one},
		"no request":      {8080, nil},
		"five requests":   {8080, [][]byte{one[0], one[0], one[0], one[0], one[0]}},
		"empty request":   {8080, [][]byte{{}}},
		"request too big": {8080, [][]byte{make([]byte, MaxRequestBytes+1)}},
	}
	for name, tt := range tests {
		rec := withBuilds(networkRecorder(goodCanary, 0), 0)
		s := startedApp(t, rec)
		before := len(rec.to("run"))
		if _, err := s.Exchange(context.Background(), tt.port, tt.requests); !errors.Is(err, ErrSpec) {
			t.Errorf("%s: %v", name, err)
		}
		if len(rec.to("run")) != before {
			t.Errorf("%s: a container started", name)
		}
	}
	leak := withBuilds(networkRecorder(goodCanary, 0), 0)
	s := startedApp(t, leak)
	leak.reply = func(_ context.Context, args []string) (cliResult, error) {
		return cliResult{stdout: []byte(strings.Replace(goodCanary, "dns=no", "dns=yes", 1))}, nil
	}
	if _, err := s.Exchange(context.Background(), 8080, one); !errors.Is(err, ErrNetworkLeak) {
		t.Errorf("Exchange after a leaking canary: %v", err)
	}
	if slices.ContainsFunc(leak.to("run"), isRunnerRun) {
		t.Error("the runner started after the canary leaked")
	}
}
