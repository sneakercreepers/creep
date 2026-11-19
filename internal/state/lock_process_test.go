package state

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The test binary doubles as a second creep process: with lockChildEnv set
// it opens the store in lockDirEnv and does what the env value says.
const (
	lockChildEnv = "CREEP_STATE_LOCK_CHILD"
	lockDirEnv   = "CREEP_STATE_LOCK_DIR"
	lockRunEnv   = "CREEP_STATE_LOCK_RUN"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(lockChildEnv); mode != "" {
		os.Exit(lockChild(mode, os.Getenv(lockDirEnv), os.Getenv(lockRunEnv)))
	}
	os.Exit(m.Run())
}

// lockChild "hold"s a new run (one step, then a second step once stdin
// closes) or "try"s to open one and prints what happened.
func lockChild(mode, dir, id string) int {
	s, err := OpenWithSecret(dir, testSecret)
	if err != nil {
		fmt.Println("open:", err)
		return 1
	}
	defer s.Close()
	if mode == "try" {
		_, errNew := s.NewRun(ModeLive)
		_, errResume := s.Resume(id)
		fmt.Println(errors.Is(errNew, ErrLocked), errors.Is(errResume, ErrLocked))
		return 0
	}
	r, err := s.NewRun(ModeLive)
	if err == nil {
		err = r.StepDone("child-1")
	}
	if err != nil {
		fmt.Println("hold:", err)
		return 1
	}
	fmt.Println("ready", r.ID())
	_, _ = io.Copy(io.Discard, os.Stdin)
	if err := r.StepDone("child-2"); err != nil {
		return 1
	}
	return closeErr(r.Close())
}

func closeErr(err error) int {
	if err != nil {
		return 1
	}
	return 0
}

// holder is a child process holding a run on dir.
type holder struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	id    string
}

func startHolder(t *testing.T, dir string) *holder {
	t.Helper()
	cmd := childCmd(t, "hold", dir, "")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	id, ok := strings.CutPrefix(strings.TrimSpace(line), "ready ")
	if err != nil || !ok {
		t.Fatalf("holder said %q, %v", line, err)
	}
	return &holder{cmd: cmd, stdin: stdin, id: id}
}

func childCmd(t *testing.T, mode, dir, id string) *exec.Cmd {
	ctx, cancel := context.WithTimeout(context.Background(), 4*lockDeadline)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), lockChildEnv+"="+mode, lockDirEnv+"="+dir, lockRunEnv+"="+id)
	return cmd
}

// Acceptance (#160): while one creep process has a run open, a second
// process (or this one) cannot start or resume a run on the same state; it
// fails at once instead of interleaving appends, and the first run's log
// loads with every line it wrote.
func TestLockAcrossProcesses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".creep")
	s, err := OpenWithSecret(dir, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := startHolder(t, dir)
	if _, err := s.NewRun(ModeLive); !errors.Is(err, ErrLocked) {
		t.Fatalf("NewRun beside another process err = %v; want ErrLocked", err)
	}
	if _, err := s.Resume(h.id); !errors.Is(err, ErrLocked) {
		t.Fatalf("Resume beside another process err = %v; want ErrLocked", err)
	}
	out, err := childCmd(t, "try", dir, h.id).Output()
	if err != nil || strings.TrimSpace(string(out)) != "true true" {
		t.Fatalf("third process got %q, %v; want both refused with ErrLocked", out, err)
	}
	_ = h.stdin.Close()
	if err := h.cmd.Wait(); err != nil {
		t.Fatalf("holder: %v", err)
	}
	sum, err := s.Load(h.id)
	if err != nil || !slices.Equal(sum.Steps, []string{"child-1", "child-2"}) {
		t.Fatalf("holder's log = %+v, %v; want both steps", sum, err)
	}
	r, err := s.Resume(h.id)
	if err != nil {
		t.Fatalf("Resume after the holder exited: %v", err)
	}
	_ = r.Close()
}

// A creep that dies holding the lock does not wedge the directory: the OS
// drops the lock with the process, and its run stays resumable.
func TestLockReleasedWhenHolderDies(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".creep")
	h := startHolder(t, dir)
	if err := h.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = h.cmd.Wait()
	s, err := OpenWithSecret(dir, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.Resume(h.id)
	if err != nil {
		t.Fatalf("Resume after the holder died: %v", err)
	}
	defer r.Close()
	if !r.Done("child-1") || r.Summary().Ended {
		t.Fatalf("dead holder's run = %+v; want one step, not ended", r.Summary())
	}
}
