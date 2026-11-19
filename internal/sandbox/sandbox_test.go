package sandbox

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// blockUntilDone answers a run call only when ctx ends, like a container
// that never exits; other calls succeed at once.
func blockUntilDone(ctx context.Context, args []string) (cliResult, error) {
	if subcommand(args) != "run" {
		return cliResult{}, nil
	}
	<-ctx.Done()
	return cliResult{}, ctx.Err()
}

func runName(t *testing.T, rec *recorder) string {
	t.Helper()
	runs := rec.to("run")
	if len(runs) != 1 {
		t.Fatalf("got %d run calls", len(runs))
	}
	for _, a := range runs[0] {
		if name, ok := strings.CutPrefix(a, "--name="); ok {
			return name
		}
	}
	t.Fatal("run without --name")
	return ""
}

func removed(rec *recorder, name string) bool {
	for _, c := range rec.to("rm") {
		if slices.Contains(c, "--force") && slices.Contains(c, name) {
			return true
		}
	}
	return false
}

// TestRunCleansUpWhenCut covers timeout, Ctrl+C, a canceled caller and a
// runtime that refused to start the container: each removes the container
// and says why.
func TestRunCleansUpWhenCut(t *testing.T) {
	tests := []struct {
		name  string
		reply func(context.Context, []string) (cliResult, error)
		spec  Spec
		cut   func(s *Sandbox, cancel context.CancelFunc)
		want  error
	}{
		{"timeout", blockUntilDone, Spec{Image: testImage, Timeout: 50 * time.Millisecond}, nil, ErrTimeout},
		{"interrupt", blockUntilDone, Spec{Image: testImage}, interruptSoon, ErrInterrupted},
		{"caller canceled", blockUntilDone, Spec{Image: testImage}, func(_ *Sandbox, cancel context.CancelFunc) {
			time.AfterFunc(20*time.Millisecond, cancel)
		}, context.Canceled},
		{"runtime refused", func(_ context.Context, args []string) (cliResult, error) {
			return cliResult{exit: 125}, nil
		}, Spec{Image: testImage}, nil, ErrStart},
		{"cli did not start", func(_ context.Context, args []string) (cliResult, error) {
			if subcommand(args) == "run" {
				return cliResult{}, errors.New("exec: no such file")
			}
			return cliResult{}, nil
		}, Spec{Image: testImage}, nil, ErrStart},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{reply: tt.reply}
			s := testSandbox(t, rec)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cut != nil {
				tt.cut(s, cancel)
			}
			_, err := s.Run(ctx, tt.spec)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if name := runName(t, rec); !removed(rec, name) {
				t.Errorf("container %s was not removed; calls %q", name, rec.calls)
			}
		})
	}
}

// interruptSoon replaces the signal hook with one that delivers Ctrl+C
// shortly after Run starts waiting.
func interruptSoon(s *Sandbox, _ context.CancelFunc) {
	s.notify = func(c chan<- os.Signal) {
		time.AfterFunc(20*time.Millisecond, func() { c <- os.Interrupt })
	}
	s.stop = func(chan<- os.Signal) {}
}

func TestRunReturnsContainerResult(t *testing.T) {
	rec := &recorder{reply: func(_ context.Context, args []string) (cliResult, error) {
		if subcommand(args) == "run" {
			return cliResult{stdout: []byte("pwned"), exit: 1, truncated: true}, nil
		}
		return cliResult{}, nil
	}}
	s := testSandbox(t, rec)
	res, err := s.Run(context.Background(), Spec{Image: testImage})
	if err != nil || res.ExitCode != 1 || string(res.Output) != "pwned" || !res.Truncated {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	if len(rec.to("rm")) != 0 {
		t.Error("a finished --rm container needs no removal")
	}
}

// TestCloseRemovesRunContainers checks Close lists only this run's
// containers, removes them and the work directory.
func TestCloseRemovesRunContainers(t *testing.T) {
	rec := &recorder{reply: func(_ context.Context, args []string) (cliResult, error) {
		if subcommand(args) == "ps" {
			return cliResult{stdout: []byte(fakeID + "\n")}, nil
		}
		return cliResult{}, nil
	}}
	s := testSandbox(t, rec)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	ps := rec.to("ps")[0]
	if !slices.Contains(ps, "label="+LabelRun+"="+testRunID) || !slices.Contains(ps, "--all") {
		t.Errorf("ps = %q", ps)
	}
	if !removed(rec, fakeID) {
		t.Errorf("run container not removed: %q", rec.calls)
	}
	if _, err := os.Stat(s.work); !os.IsNotExist(err) {
		t.Errorf("work directory left: %v", err)
	}
}

// TestRemoveLabeledRefusesOddOutput: nothing but hex IDs becomes an rm
// argument, and a failing runtime is an error, not "nothing to clean".
func TestRemoveLabeledRefusesOddOutput(t *testing.T) {
	tests := map[string]cliResult{
		"flag in list":   {stdout: []byte("--all\n")},
		"name not id":    {stdout: []byte("creep-x\n")},
		"short id":       {stdout: []byte("abc\n")},
		"truncated list": {stdout: []byte(fakeID), truncated: true},
		"ps failed":      {exit: 1},
	}
	for name, ps := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{reply: func(_ context.Context, args []string) (cliResult, error) {
				if subcommand(args) == "ps" {
					return ps, nil
				}
				return cliResult{}, nil
			}}
			if _, err := removeLabeled(context.Background(), rec.run, usableDocker(), LabelManaged+"=true"); err == nil {
				t.Fatal("accepted")
			}
			if len(rec.to("rm")) != 0 {
				t.Errorf("rm ran: %q", rec.to("rm"))
			}
		})
	}
}

// TestRemoveLabeledBatches removes a killed run's many containers in
// bounded rm calls through the pinned endpoint.
func TestRemoveLabeledBatches(t *testing.T) {
	var list strings.Builder
	for i := range 250 {
		list.WriteString(fakeID[:60] + string("0123456789abcdef"[i%16]) + string("0123456789abcdef"[i/16%16]) + "ab\n")
	}
	rec := &recorder{reply: func(_ context.Context, args []string) (cliResult, error) {
		if subcommand(args) == "ps" {
			return cliResult{stdout: []byte(list.String())}, nil
		}
		return cliResult{}, nil
	}}
	n, err := removeLabeled(context.Background(), rec.run, usableDocker(), LabelManaged+"=true")
	if err != nil || n != 250 {
		t.Fatalf("removed %d, %v", n, err)
	}
	rms := rec.to("rm")
	if len(rms) != 3 {
		t.Fatalf("got %d rm calls, want 3", len(rms))
	}
	for _, c := range rms {
		if c[0] != "--host="+usableDocker().Host || len(c) > removeBatch+3 {
			t.Errorf("rm call %d args, first %q", len(c), c[0])
		}
	}
}

func TestCleanNeedsReachableRuntime(t *testing.T) {
	_, err := Clean(context.Background(), Status{Runtime: Podman, Reason: ReasonRemoteEndpoint})
	if !errors.Is(err, ErrNotReachable) {
		t.Errorf("err = %v", err)
	}
}
