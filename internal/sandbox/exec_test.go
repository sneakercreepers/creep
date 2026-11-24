package sandbox

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"testing"
	"time"
)

// TestThroughRealExec drives Detect, Open, Run and Close through the real
// exec path with the fake docker: the CLI never sees the operator's keys,
// proxies, DOCKER_HOST or repository PATH entries (the fake exits 42 if it
// does), every run is hardened, and Close removes the run's containers.
func TestThroughRealExec(t *testing.T) {
	bin := installFake(t, "docker")
	getenv, repo := hostileEnv(t, t.TempDir())
	p := prober{look: func(name string) (string, error) {
		if name == "docker" {
			return bin, nil
		}
		return "", exec.ErrNotFound
	}, start: newExecRunner}
	rep := detect(context.Background(), Env{Repo: repo, Getenv: getenv}, p)
	st, ok := rep.Best()
	if !ok || st.Isolation != IsolationRootless || st.Host != "unix:///run/user/1000/docker.sock" {
		t.Fatalf("detect = %+v", rep.Checked)
	}
	s, err := Open(st, testRunID, Mirror{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Run(context.Background(), Spec{Image: testImage, Cmd: []string{"python", "poc.py"}})
	if err != nil || res.ExitCode != 3 || string(res.Output) != "poc output" {
		t.Fatalf("Run = %+v, %v (exit 42 means the environment leaked)", res, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	calls := fakeCalls(t, bin)
	for _, argv := range callsTo(calls, "run") {
		if p := hardeningProblems(argv); len(p) > 0 {
			t.Errorf("run %q: %v", argv, p)
		}
	}
	rm := callsTo(calls, "rm")
	if len(rm) != 1 || !slices.Contains(rm[0], fakeID) {
		t.Errorf("rm calls %q", rm)
	}
}

// TestOperatorProxiesNeverReachContainers is the protection test for the
// operator's proxy settings: the CLI that starts a container reads an
// empty DOCKER_CONFIG, every proxy variable is set empty, and a spec cannot
// set one. The broken path (the operator's config passed to run) is caught.
func TestOperatorProxiesNeverReachContainers(t *testing.T) {
	bin := installFake(t, "docker")
	st := usableDocker()
	st.Path, st.env = bin, []string{"DOCKER_CONFIG=" + proxiedDockerConfig(t)}
	s, err := Open(st, testRunID, Mirror{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	res, err := s.Run(context.Background(), Spec{Image: testImage})
	if err != nil || res.ExitCode != 3 {
		t.Fatalf("Run = %+v, %v (exit 42: the operator's docker config reached run)", res, err)
	}
	for _, argv := range callsTo(fakeCalls(t, bin), "run") {
		if p := hardeningProblems(argv); len(p) > 0 {
			t.Errorf("run %q: %v", argv, p)
		}
	}
	for _, name := range []string{"HTTP_PROXY", "https_proxy", "All_Proxy", "no_proxy"} {
		if _, err := s.Run(context.Background(), Spec{Image: testImage, Env: map[string]string{name: "http://x"}}); !errors.Is(err, ErrSpec) {
			t.Errorf("spec env %s: %v", name, err)
		}
	}
	broken := newExecRunner(bin, st.env)
	argv, err := s.runArgs("creep-"+testRunID+"-9", Spec{Image: testImage})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := broken(context.Background(), argv, 1024); err != nil || res.exit != 42 {
		t.Errorf("run with the operator's config was not caught: exit %d, %v", res.exit, err)
	}
}

func TestExecBounds(t *testing.T) {
	t.Run("stdout capped", func(t *testing.T) {
		run := newExecRunner(installFake(t, "flood"), nil)
		res, err := run(context.Background(), []string{"info"}, 1024)
		if err != nil || len(res.stdout) != 1024 || !res.truncated {
			t.Fatalf("len %d truncated %v err %v", len(res.stdout), res.truncated, err)
		}
	})
	t.Run("timeout kills", func(t *testing.T) {
		run := newExecRunner(installFake(t, "slow"), nil)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		start := time.Now()
		if _, err := run(ctx, []string{"info"}, 1024); err == nil {
			t.Fatal("a hung CLI returned no error")
		}
		if time.Since(start) > 20*time.Second {
			t.Errorf("took %s", time.Since(start))
		}
	})
	t.Run("missing binary", func(t *testing.T) {
		run := newExecRunner(t.TempDir()+"/nothing", nil)
		if _, err := run(context.Background(), []string{"info"}, 1024); err == nil {
			t.Fatal("no error")
		}
	})
}
