package sandbox

import (
	"context"
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
	s, err := Open(st, testRunID)
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
