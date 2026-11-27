package sandbox

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// The integration tests run only where a usable runtime and the go tool
// exist (the ubuntu CI runners, a developer machine with Docker running);
// elsewhere they skip. They start real containers from a local image whose
// only program is testdata/probe, so nothing is pulled.

const (
	childEnv   = "CREEP_SANDBOX_TEST_CHILD" // image ID for the killed-run child
	requireEnv = "CREEP_REQUIRE_SANDBOX"    // set by CI on Linux: a skip there is a failure
)

// realRuntimes is every runtime Detect checked, so Podman is exercised
// wherever it works and not only when it is the best one. It skips the
// test unless at least one is usable (and fails it when CI requires one).
func realRuntimes(t *testing.T) []Status {
	t.Helper()
	rep := Detect(context.Background(), Env{Repo: t.TempDir(), Getenv: os.Getenv})
	usable := slices.ContainsFunc(rep.Checked, Status.Usable)
	_, goErr := exec.LookPath("go")
	switch {
	case usable && goErr == nil && !testing.Short():
		return rep.Checked
	case os.Getenv(requireEnv) != "":
		t.Fatalf("%s is set, so the sandbox integration tests must run: usable %v, go %v, short %v, checked %s", requireEnv, usable, goErr, testing.Short(), reasons(rep))
	case testing.Short():
		t.Skip("integration test")
	case !usable:
		t.Skipf("no usable container runtime: %s", reasons(rep))
	}
	t.Skip("no go tool to build the probe")
	return nil
}

// reasons names each checked runtime and why it is or is not usable, and
// nothing of the environment it would run with.
func reasons(rep Report) string {
	var out []string
	for _, st := range rep.Checked {
		out = append(out, string(st.Runtime)+": "+string(st.Reason))
	}
	return strings.Join(out, ", ")
}

// eachRuntime runs test once per runtime, as a subtest named after it; an
// unusable runtime's subtest skips with the reason, so `go test -v` (as in
// CI logs) shows which runtimes were exercised and why the others were not.
func eachRuntime(t *testing.T, test func(t *testing.T, st Status)) {
	for _, st := range realRuntimes(t) {
		t.Run(string(st.Runtime), func(t *testing.T) {
			if !st.Usable() {
				t.Skipf("%s not usable: %s", st.Runtime, st.Reason)
			}
			t.Logf("%s, isolation %s", st.Runtime, st.Isolation)
			test(t, st)
		})
	}
}

// cli runs the runtime CLI for the test's own setup and inspection.
func cli(t *testing.T, st Status, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := newExecRunner(st.Path, st.env)(ctx, append(globalArgs(st), args...), infoLimit)
	if err != nil || res.exit != 0 {
		t.Fatalf("%s %q: exit %d, %v", st.Runtime, args, res.exit, err)
	}
	return strings.TrimSpace(string(res.stdout))
}

// probeImage builds testdata/probe for Linux and imports it as an image
// holding that one file, with any --change instructions, removed after
// the test.
func probeImage(t *testing.T, st Status, changes ...string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "probe")
	build := exec.Command("go", "build", "-o", bin, "./testdata/probe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v\n%s", err, out)
	}
	archive := filepath.Join(dir, "image.tar")
	writeImageTar(t, archive, bin)
	args := []string{"import"}
	for _, c := range changes {
		args = append(args, "--change", c)
	}
	id := cli(t, st, append(args, archive)...)
	if !strings.HasPrefix(id, "sha256:") {
		id = "sha256:" + id
	}
	t.Cleanup(func() {
		_, _ = newExecRunner(st.Path, st.env)(context.Background(), append(globalArgs(st), "rmi", "--force", id), infoLimit)
	})
	return id
}

func writeImageTar(t *testing.T, archive, bin string) {
	t.Helper()
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := tar.NewWriter(f)
	for _, d := range []string{"tmp/", "app/", "proc/", "sys/", "dev/"} {
		if err := w.WriteHeader(&tar.Header{Name: d, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.WriteHeader(&tar.Header{Name: "probe", Mode: 0o755, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestRealContainerIsHardened checks from inside a real container that the
// profile holds (user, capabilities, no-new-privileges, seccomp, read-only
// root, writable /tmp, no network, synthetic .env read-only, no runtime
// socket, cgroup limits), then the runtime's own record of a live one.
func TestRealContainerIsHardened(t *testing.T) {
	eachRuntime(t, realContainerIsHardened)
}

func realContainerIsHardened(t *testing.T, st Status) {
	image := probeImage(t, st)
	// The operator's docker config sets proxies with a password; none of it
	// may reach the container (the probe fails on any proxy variable).
	st.env = withEnv(st.env, "DOCKER_CONFIG", proxiedDockerConfig(t))
	s, err := Open(st, "itest-"+strings.ToLower(uniqueSuffix()), Mirror{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	env, err := s.writeEnvFile(map[string]string{"SECRET_KEY": "creep-synthetic-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREEP_API_KEY", "sk-must-not-reach-the-container")
	res, err := s.Run(context.Background(), Spec{
		Image: image, Cmd: []string{"/probe", "check"}, Env: map[string]string{"APP_ENV": "test"},
		Mounts: []Mount{{Source: env, Target: "/app/.env"}}, Timeout: 2 * time.Minute,
	})
	if err != nil || res.ExitCode != 0 || string(res.Output) != "ok" {
		t.Fatalf("probe: exit %d, %v: %s", res.ExitCode, err, res.Output)
	}
	if st.Runtime == Docker {
		inspectLive(t, st, s, image)
	}
}

// TestRealImageVolumesRefused: an image that declares a VOLUME, which
// would get a writable host volume past --read-only, starts nothing.
func TestRealImageVolumesRefused(t *testing.T) {
	eachRuntime(t, func(t *testing.T, st Status) {
		image := probeImage(t, st, "VOLUME /data")
		s, err := Open(st, "itest-"+strings.ToLower(uniqueSuffix()), Mirror{})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if _, err := s.Run(context.Background(), Spec{Image: image, Cmd: []string{"/probe", "check"}}); !errors.Is(err, ErrImageVolumes) {
			t.Fatalf("image with a VOLUME: %v", err)
		}
		if left := cli(t, st, "ps", "--all", "--quiet", "--filter", "label="+LabelRun+"="+s.runID); left != "" {
			t.Errorf("a container was created: %s", left)
		}
	})
}

// hostConfig is the part of `docker inspect` the test checks.
type hostConfig struct {
	CapDrop        []string
	Privileged     bool
	ReadonlyRootfs bool
	SecurityOpt    []string
	NetworkMode    string
	PidsLimit      int64
	Memory         int64
	NanoCpus       int64
	Binds          []string
	LogConfig      struct{ Type string }
}

func inspectLive(t *testing.T, st Status, s *Sandbox, image string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.Run(ctx, Spec{Image: image, Cmd: []string{"/probe", "sleep"}}); done <- err }()
	id := waitForContainer(t, st, LabelRun+"="+s.runID)
	var hc hostConfig
	if err := json.Unmarshal([]byte(cli(t, st, "inspect", "--format", "{{json .HostConfig}}", id)), &hc); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("canceled run returned %v", err)
	}
	if len(hc.CapDrop) != 1 || !strings.EqualFold(strings.TrimPrefix(hc.CapDrop[0], "CAP_"), "ALL") || hc.Privileged ||
		!hc.ReadonlyRootfs || hc.NetworkMode != "none" || hc.PidsLimit != 128 || hc.Memory != 512<<20 ||
		hc.NanoCpus != 1e9 || len(hc.Binds) != 0 || hc.LogConfig.Type != "none" || !strings.Contains(strings.Join(hc.SecurityOpt, ","), "no-new-privileges") {
		t.Errorf("host config %+v", hc)
	}
	if left := cli(t, st, "ps", "--all", "--quiet", "--filter", "label="+LabelRun+"="+s.runID); left != "" {
		t.Errorf("canceled run left container %s", left)
	}
}

func waitForContainer(t *testing.T, st Status, label string) string {
	t.Helper()
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		if id := cli(t, st, "ps", "--quiet", "--filter", "label="+label); id != "" {
			return strings.Fields(id)[0]
		}
	}
	t.Fatalf("no container with %s", label)
	return ""
}

// TestKilledRunIsCleaned kills a creep process (a child test binary)
// while its container runs, then checks creep clean removes the orphan.
func TestKilledRunIsCleaned(t *testing.T) {
	eachRuntime(t, killedRunIsCleaned)
}

func killedRunIsCleaned(t *testing.T, st Status) {
	image := probeImage(t, st)
	runID := "itest-" + strings.ToLower(uniqueSuffix())
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(self, "-test.run=^TestKilledRunChild$")
	child.Env = append(os.Environ(), childEnv+"="+image+" "+runID+" "+string(st.Runtime))
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waitForContainer(t, st, LabelRun+"="+runID)
	_ = child.Process.Kill()
	_ = child.Wait()
	if cli(t, st, "ps", "--all", "--quiet", "--filter", "label="+LabelRun+"="+runID) == "" {
		t.Fatal("the killed run left nothing to clean; the test proves nothing")
	}
	if _, err := Clean(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if left := cli(t, st, "ps", "--all", "--quiet", "--filter", "label="+LabelManaged+"=true"); left != "" {
		t.Errorf("creep clean left %s", left)
	}
}

// TestKilledRunChild is the creep process TestKilledRunIsCleaned kills.
func TestKilledRunChild(t *testing.T) {
	args := strings.Fields(os.Getenv(childEnv))
	if len(args) != 3 {
		t.Skip("run by TestKilledRunIsCleaned only")
	}
	image, runID, rt := args[0], args[1], Runtime(args[2])
	usable := realRuntimes(t)
	i := slices.IndexFunc(usable, func(st Status) bool { return st.Runtime == rt && st.Usable() })
	if i < 0 {
		t.Fatalf("%s is not usable in the child", rt)
	}
	s, err := Open(usable[i], runID, Mirror{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Run(context.Background(), Spec{Image: image, Cmd: []string{"/probe", "sleep"}, Timeout: MaxTimeout})
}

func uniqueSuffix() string {
	return strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
}
