package sandbox

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// goodCanary is what the canary prints on a network that reaches nothing
// outside: both controls work, every probe fails.
const goodCanary = "control-dns=yes\ncontrol-tcp=yes\ndns=no\ndns-direct=no\ntcp-1.1.1.1=no\ntcp-8.8.8.8=no\n"

// pgVolumes is the database image's declared VOLUME.
var pgVolumes = cliResult{stdout: []byte(`{"/var/lib/postgresql/data":{}}`)}

// networkRecorder answers like a runtime: the canary prints canary, the
// database's readiness poll exits ready, the database image declares its
// VOLUME, and every other call succeeds with no output.
func networkRecorder(canary string, ready int) *recorder {
	return &recorder{
		images: map[string]cliResult{DatabaseImage: pgVolumes},
		reply: func(_ context.Context, args []string) (cliResult, error) {
			switch {
			case subcommand(args) == "run" && slices.Contains(args, CanaryImage):
				return cliResult{stdout: []byte(canary)}, nil
			case subcommand(args) == "run" && slices.Contains(args, DatabaseImage) && !slices.Contains(args, "--detach"):
				return cliResult{exit: ready}, nil
			}
			return cliResult{}, nil
		},
	}
}

func leakCases() map[string]string {
	cases := map[string]string{}
	for _, c := range canaryChecks {
		if !c.control {
			cases["leak "+c.key] = strings.Replace(goodCanary, c.key+"=no", c.key+"=yes", 1)
		}
	}
	return cases
}

// TestCanaryLeakAbortsRun is the protection test for the network canary:
// when the canary gets through (each probe in turn), cannot tell (a
// control fails, the answer is odd, the canary fails), no PoC of the batch
// starts and the run is aborted: every later Run, RunBatch and
// StartDatabase fails with the same error and starts nothing.
func TestCanaryLeakAbortsRun(t *testing.T) {
	tests := map[string]struct {
		canary string
		want   error
	}{
		"control dns fails":   {strings.Replace(goodCanary, "control-dns=yes", "control-dns=no", 1), ErrCanary},
		"control tcp fails":   {strings.Replace(goodCanary, "control-tcp=yes", "control-tcp=no", 1), ErrCanary},
		"leak and no control": {"control-dns=no\ncontrol-tcp=no\ndns=yes\ndns-direct=no\ntcp-1.1.1.1=no\ntcp-8.8.8.8=no\n", ErrNetworkLeak},
		"missing check":       {strings.Replace(goodCanary, "dns-direct=no\n", "", 1), ErrCanary},
		"duplicate check":     {goodCanary + "dns=no\n", ErrCanary},
		"unknown check":       {goodCanary + "tcp-9.9.9.9=no\n", ErrCanary},
		"odd value":           {strings.Replace(goodCanary, "dns=no", "dns=maybe", 1), ErrCanary},
		"extra text":          {"nc: bad address\n" + goodCanary, ErrCanary},
		"empty":               {"", ErrCanary},
	}
	for name, canary := range leakCases() {
		tests[name] = struct {
			canary string
			want   error
		}{canary, ErrNetworkLeak}
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rec := networkRecorder(tt.canary, 0)
			s := testSandbox(t, rec)
			if _, err := s.RunBatch(context.Background(), []Spec{{Image: testImage}}); !errors.Is(err, tt.want) {
				t.Fatalf("RunBatch: %v, want %v", err, tt.want)
			}
			assertAborted(t, s, rec, tt.want)
		})
	}
}

// assertAborted checks that the aborted run starts nothing more.
func assertAborted(t *testing.T, s *Sandbox, rec *recorder, want error) {
	t.Helper()
	if _, err := s.RunBatch(context.Background(), []Spec{{Image: testImage}}); !errors.Is(err, want) {
		t.Errorf("RunBatch after abort: %v", err)
	}
	if _, err := s.Run(context.Background(), Spec{Image: testImage}); !errors.Is(err, want) {
		t.Errorf("Run after abort: %v", err)
	}
	if _, err := s.StartDatabase(context.Background(), nil); !errors.Is(err, want) {
		t.Errorf("StartDatabase after abort: %v", err)
	}
	for _, argv := range rec.to("run") {
		if !slices.Contains(argv, CanaryImage) {
			t.Errorf("a container other than the canary started: %q", argv)
		}
	}
	if n := len(rec.to("run")); n != 1 {
		t.Errorf("%d canaries ran, want 1: the abort must stick", n)
	}
}

// TestCanaryFailureAbortsRun: a canary that cannot run, exits non-zero or
// floods its output is inconclusive, which aborts the run like a leak.
func TestCanaryFailureAbortsRun(t *testing.T) {
	tests := map[string]func(context.Context, []string) (cliResult, error){
		"exit 1": func(context.Context, []string) (cliResult, error) {
			return cliResult{stdout: []byte(goodCanary), exit: 1}, nil
		},
		"truncated": func(context.Context, []string) (cliResult, error) {
			return cliResult{stdout: []byte(goodCanary), truncated: true}, nil
		},
		"refused": func(context.Context, []string) (cliResult, error) { return cliResult{exit: 125}, nil },
		"no cli":  func(context.Context, []string) (cliResult, error) { return cliResult{}, errors.New("exec: not found") },
	}
	for name, reply := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{reply: func(ctx context.Context, args []string) (cliResult, error) {
				if subcommand(args) == "run" {
					return reply(ctx, args)
				}
				return cliResult{}, nil
			}}
			s := testSandbox(t, rec)
			if _, err := s.RunBatch(context.Background(), []Spec{{Image: testImage}}); !errors.Is(err, ErrCanary) {
				t.Fatalf("RunBatch: %v", err)
			}
			assertAborted(t, s, rec, ErrCanary)
		})
	}
}

// TestBatchRunsOnNetworkAfterCanary: a clean canary lets the batch run,
// each container on the run's network, after a fresh canary per batch.
func TestBatchRunsOnNetworkAfterCanary(t *testing.T) {
	rec := networkRecorder(goodCanary, 0)
	s := testSandbox(t, rec)
	for range 2 {
		res, err := s.RunBatch(context.Background(), []Spec{{Image: testImage}, {Image: testImage}})
		if err != nil || len(res) != 2 {
			t.Fatalf("RunBatch: %d results, %v", len(res), err)
		}
	}
	runs := rec.to("run")
	if len(runs) != 6 || !slices.Contains(runs[0], CanaryImage) || !slices.Contains(runs[3], CanaryImage) {
		t.Fatalf("want canary, 2 PoCs, canary, 2 PoCs: %q", runs)
	}
	if slices.Contains(runs[0], "--network-alias=canary-1") == slices.Contains(runs[3], "--network-alias=canary-1") {
		t.Error("two canaries share an alias")
	}
	for _, argv := range runs {
		if !slices.Contains(argv, "--network=creep-"+testRunID) {
			t.Errorf("not on the run network: %q", argv)
		}
	}
	if n := len(rec.to("network")); n != 1 {
		t.Errorf("%d network calls, want one create", n)
	}
	for _, bad := range [][]Spec{nil, make([]Spec, maxBatch+1)} {
		if _, err := s.RunBatch(context.Background(), bad); !errors.Is(err, ErrSpec) {
			t.Errorf("batch of %d: %v", len(bad), err)
		}
	}
}

// TestNetworkCreateFails: a network that cannot be created (a name taken
// by someone else's network, a dead CLI) starts no container and removes
// nothing that is not labeled as this run's.
func TestNetworkCreateFails(t *testing.T) {
	tests := map[string]func() (cliResult, error){
		"name taken":        func() (cliResult, error) { return cliResult{exit: 1}, nil },
		"cli did not start": func() (cliResult, error) { return cliResult{}, errors.New("exec: not found") },
	}
	for name, create := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{reply: func(_ context.Context, args []string) (cliResult, error) {
				if subcommand(args) == "network" && slices.Contains(args, "create") {
					return create()
				}
				return cliResult{}, nil
			}}
			s := testSandbox(t, rec)
			if _, err := s.RunBatch(context.Background(), []Spec{{Image: testImage}}); !errors.Is(err, ErrStart) {
				t.Fatalf("RunBatch: %v", err)
			}
			if len(rec.to("run")) != 0 {
				t.Error("a container started without a network")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			for _, c := range rec.to("network") {
				if slices.Contains(c, "ls") && !slices.Contains(c, "label="+LabelRun+"="+testRunID) {
					t.Errorf("network lookup not by this run's label: %q", c)
				}
			}
		})
	}
}

// TestCloseRemovesNetwork: Close removes the run's containers, then its
// networks by label and hex ID only, and refuses a listing that holds
// anything else.
func TestCloseRemovesNetwork(t *testing.T) {
	tests := map[string]struct {
		list    string
		wantErr bool
	}{
		"one network": {fakeID + "\n", false},
		"none":        {"", false},
		"a name":      {"creep-" + testRunID + "\n", true},
		"a flag":      {"--force\n", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{reply: func(_ context.Context, args []string) (cliResult, error) {
				if subcommand(args) == "network" && slices.Contains(args, "ls") {
					return cliResult{stdout: []byte(tt.list)}, nil
				}
				return cliResult{}, nil
			}}
			s := testSandbox(t, rec)
			if err := s.Close(); (err != nil) != tt.wantErr {
				t.Fatalf("Close: %v", err)
			}
			checkNetworkRemoval(t, rec, tt.list != "" && !tt.wantErr)
		})
	}
}

func checkNetworkRemoval(t *testing.T, rec *recorder, wantRemoved bool) {
	t.Helper()
	psAt, lsAt, rmAt := -1, -1, -1
	for i, c := range rec.calls {
		switch {
		case subcommand(c) == "ps" && psAt < 0:
			psAt = i
		case subcommand(c) == "network" && slices.Contains(c, "ls"):
			lsAt = i
		case subcommand(c) == "network" && slices.Contains(c, "rm"):
			rmAt = i
			if !slices.Equal(c[len(c)-2:], []string{"rm", fakeID}) {
				t.Errorf("network rm %q", c)
			}
		}
	}
	if lsAt < psAt {
		t.Errorf("networks listed before containers were removed: %q", rec.calls)
	}
	if (rmAt >= 0) != wantRemoved {
		t.Errorf("network removed %v, want %v: %q", rmAt >= 0, wantRemoved, rec.calls)
	}
}

// TestCanaryScript: the script is one plain line naming every check and
// the canary's own alias, so a broken builder cannot drop a probe.
func TestCanaryScript(t *testing.T) {
	script := canaryScript("canary-7")
	if !plainValue(script) {
		t.Fatalf("script is not one plain line: %q", script)
	}
	for _, c := range canaryChecks {
		if !strings.Contains(script, "echo "+c.key+"=$("+c.probe+" "+strings.ReplaceAll(c.cmd, "{alias}", "canary-7")+")") {
			t.Errorf("script lacks %s", c.key)
		}
	}
	if err := judgeCanary([]byte(goodCanary)); err != nil {
		t.Errorf("good canary: %v", err)
	}
}
