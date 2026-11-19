package sandbox

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testRunID = "20261119T120000Z-0123abcd"
	testImage = "registry.example/poc@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// recorder is a fake runtime CLI: it records every argv and answers with
// reply, or exit 0 and no output.
type recorder struct {
	mu    sync.Mutex
	calls [][]string
	reply func(ctx context.Context, args []string) (cliResult, error)
}

func (r *recorder) run(ctx context.Context, args []string, _ int) (cliResult, error) {
	r.mu.Lock()
	r.calls = append(r.calls, slices.Clone(args))
	r.mu.Unlock()
	if r.reply != nil {
		return r.reply(ctx, args)
	}
	return cliResult{}, nil
}

func (r *recorder) to(sub string) [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return callsTo(r.calls, sub)
}

func usableDocker() Status {
	return Status{Runtime: Docker, Host: "unix:///run/user/1000/docker.sock", Reachable: true,
		Rootless: true, Isolation: IsolationRootless, Reason: ReasonOK}
}

func testSandbox(t *testing.T, rec *recorder) *Sandbox {
	t.Helper()
	s, err := newSandbox(usableDocker(), testRunID, rec.run)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// requiredOptions must appear, exactly, in every run command line. The
// list is written here, not taken from the builder, so a builder change
// that weakens the profile fails this test.
var requiredOptions = []string{
	"--rm", "--pull=never", "--network=none", "--cap-drop=ALL",
	"--security-opt=no-new-privileges", "--read-only", "--user=65534:65534",
	"--pids-limit=128", "--memory=512m", "--memory-swap=512m", "--cpus=1", "--ipc=private",
	"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
	"--label=" + LabelManaged + "=true", "--label=" + LabelRun + "=" + testRunID,
}

// hardeningProblems checks one `run` argv: every required option, and no
// option outside an allowlist, so a flag that adds privilege, a network, a
// device, a writable or socket mount or a host variable is caught.
func hardeningProblems(argv []string) []string {
	run := slices.Index(argv, "run")
	if run < 0 {
		return []string{"no run subcommand"}
	}
	var opts []string
	for _, a := range argv[run+1:] {
		if !strings.HasPrefix(a, "-") {
			break // the image: what follows is the container's command
		}
		opts = append(opts, a)
	}
	var problems []string
	for _, want := range requiredOptions {
		if !slices.Contains(opts, want) {
			problems = append(problems, "missing "+want)
		}
	}
	for _, o := range opts {
		if !allowedOption(o) {
			problems = append(problems, "not allowed: "+o)
		}
	}
	return problems
}

func allowedOption(o string) bool {
	switch {
	case slices.Contains(requiredOptions, o):
		return true
	case strings.HasPrefix(o, "--name=creep-"+testRunID+"-"):
		return true
	case strings.HasPrefix(o, "--env="):
		name, _, ok := strings.Cut(strings.TrimPrefix(o, "--env="), "=")
		return ok && envName.MatchString(name)
	case strings.HasPrefix(o, "--mount=type=bind,source="):
		src, _, _ := strings.Cut(strings.TrimPrefix(o, "--mount=type=bind,source="), ",")
		return strings.HasSuffix(o, ",readonly") && strings.Count(o, ",") == 3 && !hostPath(src)
	}
	return false
}

// TestEveryContainerIsHardened is the protection test for the profile:
// every container Run starts, whatever the spec, gets the hardened options
// and nothing else, and the endpoint stays pinned.
func TestEveryContainerIsHardened(t *testing.T) {
	rec := &recorder{}
	s := testSandbox(t, rec)
	env, err := s.WriteSyntheticEnv([]string{"DATABASE_URL", "SECRET_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	specs := []Spec{
		{Image: testImage},
		{Image: "sha256:" + strings.Repeat("ab", 32), Cmd: []string{"--privileged", "-v", "/:/host"}},
		{Image: testImage, Env: map[string]string{"APP_ENV": "test", "PORT": "8080"}},
		{Image: testImage, Mounts: []Mount{{Source: env, Target: "/app/.env"}}, Timeout: MaxTimeout},
	}
	for _, spec := range specs {
		if _, err := s.Run(context.Background(), spec); err != nil {
			t.Fatalf("Run(%+v): %v", spec, err)
		}
	}
	runs := rec.to("run")
	if len(runs) != len(specs) {
		t.Fatalf("got %d run calls, want %d", len(runs), len(specs))
	}
	for _, argv := range runs {
		if p := hardeningProblems(argv); len(p) > 0 {
			t.Errorf("run %q: %v", argv, p)
		}
		if argv[0] != "--host="+usableDocker().Host {
			t.Errorf("run %q: endpoint not pinned first", argv)
		}
	}
}

// TestHardeningCheckCatchesWeakenedRun proves the protection can fail:
// each weakened command line is caught.
func TestHardeningCheckCatchesWeakenedRun(t *testing.T) {
	s := testSandbox(t, &recorder{})
	good, err := s.runArgs("creep-"+testRunID+"-1", Spec{Image: testImage})
	if err != nil {
		t.Fatal(err)
	}
	if p := hardeningProblems(good); len(p) > 0 {
		t.Fatalf("the real profile fails the check: %v", p)
	}
	insert := func(extra string) []string {
		i := slices.Index(good, "run") + 1
		return slices.Insert(slices.Clone(good), i, extra)
	}
	weakened := map[string][]string{
		"privileged":         insert("--privileged"),
		"cap-add":            insert("--cap-add=SYS_ADMIN"),
		"host network":       insert("--network=host"),
		"seccomp unconfined": insert("--security-opt=seccomp=unconfined"),
		"docker.sock volume": insert("--volume=/var/run/docker.sock:/var/run/docker.sock"),
		"api socket":         insert("--use-api-socket"),
		"host env copied":    insert("--env=HOME"),
		"env file":           insert("--env-file=.env"),
		"writable mount":     insert("--mount=type=bind,source=/work/a,target=/a"),
		"socket mount":       insert("--mount=type=bind,source=/run/docker.sock,target=/a,readonly"),
		"root user":          insert("--user=0"),
		"device":             insert("--device=/dev/kvm"),
		"host pid":           insert("--pid=host"),
	}
	for i, opt := range good {
		if slices.Contains(requiredOptions, opt) {
			weakened["without "+opt] = slices.Delete(slices.Clone(good), i, i+1)
		}
	}
	for name, argv := range weakened {
		if len(hardeningProblems(argv)) == 0 {
			t.Errorf("%s: weakened run %q passed the check", name, argv)
		}
	}
}

func TestRunRefusesSpec(t *testing.T) {
	tests := map[string]Spec{
		"tag only":              {Image: "python:3.12"},
		"flag as image":         {Image: "--privileged"},
		"digest after a flag":   {Image: "-x@sha256:" + strings.Repeat("0", 64)},
		"short digest":          {Image: "poc@sha256:abc"},
		"bad env name":          {Image: testImage, Env: map[string]string{"A=B": "c"}},
		"env name is a flag":    {Image: testImage, Env: map[string]string{"-e": "c"}},
		"newline in env":        {Image: testImage, Env: map[string]string{"A": "x\nB=y"}},
		"NUL in command":        {Image: testImage, Cmd: []string{"a\x00b"}},
		"too many arguments":    {Image: testImage, Cmd: make([]string, maxArgs+1)},
		"timeout too long":      {Image: testImage, Timeout: MaxTimeout + time.Second},
		"negative timeout":      {Image: testImage, Timeout: -time.Second},
		"mount outside workdir": {Image: testImage, Mounts: []Mount{{Source: "/etc/hostname", Target: "/x"}}},
	}
	for name, spec := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{}
			s := testSandbox(t, rec)
			if _, err := s.Run(context.Background(), spec); err == nil {
				t.Fatal("Run accepted the spec")
			}
			if len(rec.to("run")) != 0 {
				t.Error("a refused spec still started a container")
			}
		})
	}
}

func TestOpenRefuses(t *testing.T) {
	if _, err := Open(Status{Runtime: Docker, Reason: ReasonNoSeccomp}, testRunID); !errors.Is(err, ErrUnusable) {
		t.Errorf("unusable runtime: %v", err)
	}
	for _, id := range []string{"", "-rm", "a b", "a/b", strings.Repeat("a", 65)} {
		if _, err := newSandbox(usableDocker(), id, (&recorder{}).run); !errors.Is(err, ErrSpec) {
			t.Errorf("run ID %q: %v", id, err)
		}
	}
}
