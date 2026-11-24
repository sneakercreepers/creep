package sandbox

import (
	"context"
	"slices"
	"strings"
	"testing"
)

const (
	testBridge = "creep-mirror"
	testProxy  = "http://mirror.internal:3128"
)

var testMirror = Mirror{Bridge: testBridge, Proxy: testProxy}

func rootlessPodman() Status {
	st := usableDocker()
	st.Runtime, st.Host = Podman, ""
	return st
}

// mirrorRecorder answers like a runtime with the operator's network: its
// inspect prints inspect, the canary prints canary, builds succeed.
func mirrorRecorder(inspect cliResult, canary string) *recorder {
	rec := withBuilds(networkRecorder(canary, 0), 0)
	inner := rec.reply
	rec.reply = func(ctx context.Context, args []string) (cliResult, error) {
		if subcommand(args) == "network" && slices.Contains(args, "inspect") {
			return inspect, nil
		}
		return inner(ctx, args)
	}
	return rec
}

var internalBridge = cliResult{stdout: []byte("bridge/true/false\n")}

func mirrorBuild(t *testing.T, st Status, m Mirror, rec *recorder, dockerfile string) App {
	t.Helper()
	s, err := newSandbox(st, testRunID, rec.run)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	s.mirror = m
	app, err := s.Build(context.Background(), dockerfileRepo(dockerfile))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return app
}

// offlineView is a mirrored build line as the offline check reads it: the
// operator's network back to none and the proxy build arguments dropped.
func offlineView(argv []string) []string {
	out := []string{}
	for _, a := range argv {
		switch {
		case a == "--network="+testBridge:
			out = append(out, "--network=none")
		case isProxyArg(a):
		default:
			out = append(out, a)
		}
	}
	return out
}

func isProxyArg(a string) bool {
	kv, ok := strings.CutPrefix(a, "--build-arg=")
	name, value, _ := strings.Cut(kv, "=")
	return ok && slices.Contains(proxyBuildArgs, name) && value == testProxy
}

// TestBuildMirrorConfined is the protection test for ADR 0029: with a
// mirror, the only change to the build line is the operator's network in
// place of none and the four proxy build arguments, on rootless Podman
// only; everything the offline build has (no pull, no cache, labels,
// limits, no host proxy, the staged context) stays. Before the build, the
// network is inspected in a fixed format and a hardened canary on it must
// reach itself and nothing public.
func TestBuildMirrorConfined(t *testing.T) {
	rec := mirrorRecorder(internalBridge, goodCanary)
	app := mirrorBuild(t, rootlessPodman(), testMirror, rec, "FROM alpine:3\nRUN pip install flask\n")
	if !app.Built() {
		t.Fatalf("Build = %+v", app)
	}
	builds := rec.to("build")
	if len(builds) != 1 {
		t.Fatalf("%d build calls", len(builds))
	}
	line := builds[0]
	if !slices.Contains(line, "--network="+testBridge) || slices.Contains(line, "--network=none") {
		t.Errorf("build %q: not on the mirror network", line)
	}
	var args []string
	for _, a := range line {
		if strings.HasPrefix(a, "--build-arg") {
			args = append(args, a)
		}
	}
	want := []string{"--build-arg=HTTP_PROXY=" + testProxy, "--build-arg=HTTPS_PROXY=" + testProxy, "--build-arg=http_proxy=" + testProxy, "--build-arg=https_proxy=" + testProxy}
	if !slices.Equal(args, want) {
		t.Errorf("build arguments %q, want %q", args, want)
	}
	if p := buildProblems(offlineView(line), Podman, mirrorWork(rec)); len(p) > 0 {
		t.Errorf("build %q loses an offline protection: %v", line, p)
	}
	inspects := rec.to("network")
	if len(inspects) != 1 || !slices.Equal(inspects[0][len(inspects[0])-3:], []string{"--format", "{{.Driver}}/{{.Internal}}/{{.IPv6Enabled}}", testBridge}) {
		t.Errorf("network calls %q, want one fixed-format inspect of the bridge", inspects)
	}
	canaryAt, buildAt := -1, -1
	for i, c := range rec.calls {
		if subcommand(c) == "run" && slices.Contains(c, CanaryImage) && slices.Contains(c, "--network="+testBridge) {
			canaryAt = i
			// --http-proxy=false is Podman's extra, a tightening the Docker-shaped check does not list.
			podmanOnly := slices.DeleteFunc(offlineView(c), func(a string) bool { return a == "--http-proxy=false" })
			if p := hardeningProblems(podmanOnly); len(p) > 0 {
				t.Errorf("canary %q is not hardened: %v", c, p)
			}
		}
		if subcommand(c) == "build" {
			buildAt = i
		}
	}
	if canaryAt < 0 || canaryAt > buildAt {
		t.Errorf("canary on the bridge at call %d, build at %d: the canary must run first", canaryAt, buildAt)
	}
}

// mirrorWork is the sandbox work directory the build line names.
func mirrorWork(rec *recorder) string {
	for _, a := range rec.to("build")[0] {
		if p, ok := strings.CutPrefix(a, "--iidfile="); ok {
			return p[:strings.LastIndexAny(p, `/\`)]
		}
	}
	return ""
}

// TestBuildMirrorRefused proves each check can fail: every refused mirror
// starts no build, is mirror_refused with a closed detail (never an
// error, so the scan goes on), and never falls back to a network.
func TestBuildMirrorRefused(t *testing.T) {
	rootful := rootlessPodman()
	rootful.Rootless = false
	leak := strings.Replace(goodCanary, "tcp-1.1.1.1=no", "tcp-1.1.1.1=yes", 1)
	cases := []struct {
		name    string
		st      Status
		m       Mirror
		inspect cliResult
		canary  string
		detail  string
	}{
		{"docker buildkit", usableDocker(), testMirror, internalBridge, goodCanary, mirrorBuilder},
		{"rootful podman", rootful, testMirror, internalBridge, goodCanary, mirrorRootful},
		{"host mode", rootlessPodman(), Mirror{Bridge: "host"}, internalBridge, goodCanary, mirrorConfig},
		{"host mode upper", rootlessPodman(), Mirror{Bridge: "Host"}, internalBridge, goodCanary, mirrorConfig},
		{"flag as name", rootlessPodman(), Mirror{Bridge: "--network=host"}, internalBridge, goodCanary, mirrorConfig},
		{"proxy without bridge", rootlessPodman(), Mirror{Proxy: testProxy}, internalBridge, goodCanary, mirrorConfig},
		{"proxy credentials", rootlessPodman(), Mirror{Bridge: testBridge, Proxy: "http://u:p@mirror:3128"}, internalBridge, goodCanary, mirrorConfig}, //nolint:gosec // G101: fake credentials the check must refuse
		{"missing network", rootlessPodman(), testMirror, cliResult{exit: 125}, goodCanary, mirrorMissing},
		{"inspect truncated", rootlessPodman(), testMirror, cliResult{stdout: internalBridge.stdout, truncated: true}, goodCanary, mirrorMissing},
		{"routed network", rootlessPodman(), testMirror, cliResult{stdout: []byte("bridge/false/false\n")}, goodCanary, mirrorNotInternal},
		{"ipv6 network", rootlessPodman(), testMirror, cliResult{stdout: []byte("bridge/true/true\n")}, goodCanary, mirrorNotInternal},
		{"macvlan", rootlessPodman(), testMirror, cliResult{stdout: []byte("macvlan/true/false\n")}, goodCanary, mirrorNotInternal},
		{"canary leak", rootlessPodman(), testMirror, internalBridge, leak, mirrorLeak},
		{"canary garbled", rootlessPodman(), testMirror, internalBridge, "nonsense\n", mirrorCanary},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := mirrorRecorder(c.inspect, c.canary)
			app := mirrorBuild(t, c.st, c.m, rec, "FROM alpine:3\nRUN true\n")
			if app.Unavailable != BuildMirrorRefused || app.Detail != c.detail {
				t.Errorf("Build = %+v, want %s/%s", app, BuildMirrorRefused, c.detail)
			}
			if b := rec.to("build"); len(b) != 0 {
				t.Errorf("a refused mirror still built: %q", b)
			}
		})
	}
}

// TestBuildMirrorKeepsChecks: a mirror adds a network for RUN steps only.
// Every Dockerfile, context and base-image check still runs first, and a
// refusal there never touches the operator's network.
func TestBuildMirrorKeepsChecks(t *testing.T) {
	cases := map[string]struct {
		dockerfile string
		want       BuildReason
		missing    []string
	}{
		"remote ADD":       {"FROM alpine:3\nADD http://evil.example/x /x\n", BuildDockerfileRefused, nil},
		"syntax directive": {"# syntax=evil/frontend\nFROM alpine:3\n", BuildDockerfileRefused, nil},
		"RUN network":      {"FROM alpine:3\nRUN --network=host true\n", BuildDockerfileRefused, nil},
		"missing base":     {"FROM alpine:3\n", BuildBaseImageMissing, []string{"alpine:3"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rec := withBuilds(mirrorRecorder(internalBridge, goodCanary), 0, c.missing...)
			app := mirrorBuild(t, rootlessPodman(), testMirror, rec, c.dockerfile)
			if app.Unavailable != c.want {
				t.Errorf("Build = %+v, want %s", app, c.want)
			}
			if n, b := rec.to("network"), rec.to("build"); len(n) != 0 || len(b) != 0 {
				t.Errorf("network calls %q, builds %q: want none", n, b)
			}
		})
	}
}

// TestDockerBuildLineIgnoresMirror: even handed a mirror, buildArgs never
// puts a Docker build on a network or gives it a build argument.
func TestDockerBuildLineIgnoresMirror(t *testing.T) {
	s := testSandbox(t, &recorder{})
	dir := s.work + "/build-1"
	got := buildArgs(s.status, testRunID, dir, dir+"/Dockerfile", "", s.work+"/iid-2", testMirror)
	want := buildArgs(s.status, testRunID, dir, dir+"/Dockerfile", "", s.work+"/iid-2", Mirror{})
	if !slices.Equal(got, want) {
		t.Errorf("Docker build line with a mirror %q, want the offline %q", got, want)
	}
}

// TestMirrorProxyPort pins the port range: a proxy port outside 1-65535
// or with a leading zero is refused instead of reaching the builder.
func TestMirrorProxyPort(t *testing.T) {
	cases := []struct {
		proxy string
		want  bool
	}{
		{"http://mirror", true},
		{"http://mirror:1", true},
		{"http://mirror:3128", true},
		{"http://mirror:65535", true},
		{"http://mirror:0", false},
		{"http://mirror:065535", false},
		{"http://mirror:65536", false},
		{"http://mirror:99999", false},
		{"http://mirror:", false},
	}
	for _, c := range cases {
		if got := (Mirror{Bridge: testBridge, Proxy: c.proxy}).Valid(); got != c.want {
			t.Errorf("proxy %q: Valid() = %v, want %v", c.proxy, got, c.want)
		}
	}
}
