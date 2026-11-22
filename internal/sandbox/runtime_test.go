package sandbox

import (
	"cmp"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const (
	dockerRootless = `{"OSType":"linux","OperatingSystem":"Ubuntu","SecurityOptions":["name=seccomp,profile=builtin","name=rootless"],"MemoryLimit":true,"PidsLimit":true,"CPUShares":true,"DefaultRuntime":"runc"}`
	dockerRootful  = `{"OSType":"linux","OperatingSystem":"Ubuntu","SecurityOptions":["name=seccomp,profile=builtin"],"MemoryLimit":true,"PidsLimit":true,"CPUShares":true,"DefaultRuntime":"runc"}`
	dockerDesktop  = `{"OSType":"linux","OperatingSystem":"Docker Desktop","SecurityOptions":["name=seccomp,profile=builtin","name=cgroupns"],"MemoryLimit":true,"PidsLimit":true,"CPUShares":true,"DefaultRuntime":"runc"}`
	podmanRootless = `{"host":{"os":"linux","serviceIsRemote":false,"cgroupControllers":["cpu","memory","pids"],"security":{"rootless":true,"seccompEnabled":true},"buildahVersion":"1.35.3","ociRuntime":{"name":"crun","version":"crun version 1.14.4\ncommit: a220ca661ce078f2c37b38c92e66cf66c012d9c1"}}}`
	// dockerPatched is `docker version --format {{json .Server}}` of an
	// engine at the minimums.
	dockerPatched = `{"Version":"25.0.2","Components":[{"Name":"Engine","Version":"25.0.2"},{"Name":"containerd","Version":"v1.6.28"},{"Name":"runc","Version":"1.1.12"},{"Name":"docker-init","Version":"0.19.0"}]}`
)

// fakeRuntime answers detection calls by subcommand.
type fakeRuntime struct {
	context string // context inspect stdout; "" fails
	info    string // info stdout; "" fails
	version string // version stdout; "" is dockerPatched, "-" fails
}

func (f fakeRuntime) runner(rec *recorder) runFunc {
	rec.reply = func(_ context.Context, args []string) (cliResult, error) {
		out := f.info
		switch subcommand(args) {
		case "context":
			out = f.context
		case "version":
			out = cmp.Or(f.version, dockerPatched)
			if out == "-" {
				out = ""
			}
		}
		if out == "" {
			return cliResult{exit: 1}, nil
		}
		return cliResult{stdout: []byte(out)}, nil
	}
	return rec.run
}

// fakeBin makes an executable file outside every repository.
func fakeBin(t *testing.T, name string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(bin, nil, 0o700); err != nil { //nolint:gosec // G703: in t.TempDir()
		t.Fatal(err)
	}
	return bin
}

func TestDetect(t *testing.T) {
	desktopCtx := `"npipe:////./pipe/dockerDesktopLinuxEngine"`
	tests := []struct {
		name   string
		docker fakeRuntime
		podman fakeRuntime
		env    map[string]string
		want   [2]Reason // docker, podman
		best   Runtime
		iso    Isolation
	}{
		{"rootless docker", fakeRuntime{context: `"unix:///run/user/1000/docker.sock"`, info: dockerRootless}, fakeRuntime{}, nil, [2]Reason{ReasonOK, ReasonNotRunning}, Docker, IsolationRootless},
		{"docker desktop is a VM", fakeRuntime{context: desktopCtx, info: dockerDesktop}, fakeRuntime{}, nil, [2]Reason{ReasonOK, ReasonNotRunning}, Docker, IsolationVM},
		{"rootless podman beats rootful docker", fakeRuntime{context: `"unix:///var/run/docker.sock"`, info: dockerRootful}, fakeRuntime{info: podmanRootless}, nil, [2]Reason{ReasonOK, ReasonOK}, Podman, IsolationRootless},
		{"tcp DOCKER_HOST refused", fakeRuntime{info: dockerRootless}, fakeRuntime{}, map[string]string{"DOCKER_HOST": "tcp://10.0.0.5:2375"}, [2]Reason{ReasonRemoteEndpoint, ReasonNotRunning}, "", IsolationNone},
		{"ssh DOCKER_HOST refused", fakeRuntime{info: dockerRootless}, fakeRuntime{}, map[string]string{"DOCKER_HOST": "ssh://me@host"}, [2]Reason{ReasonRemoteEndpoint, ReasonNotRunning}, "", IsolationNone},
		{"local DOCKER_HOST used", fakeRuntime{info: dockerRootless}, fakeRuntime{}, map[string]string{"DOCKER_HOST": "unix:///run/user/1000/docker.sock"}, [2]Reason{ReasonOK, ReasonNotRunning}, Docker, IsolationRootless},
		{"remote context refused", fakeRuntime{context: `"tcp://build.example:2376"`, info: dockerRootless}, fakeRuntime{}, nil, [2]Reason{ReasonRemoteEndpoint, ReasonNotRunning}, "", IsolationNone},
		{"remote named pipe refused", fakeRuntime{info: dockerRootless}, fakeRuntime{}, map[string]string{"DOCKER_HOST": "npipe:////buildhost/pipe/docker_engine"}, [2]Reason{ReasonRemoteEndpoint, ReasonNotRunning}, "", IsolationNone},
		{"loopback named pipe refused", fakeRuntime{info: dockerRootless}, fakeRuntime{}, map[string]string{"DOCKER_HOST": "npipe:////127.0.0.1/pipe/dockerDesktopLinuxEngine"}, [2]Reason{ReasonRemoteEndpoint, ReasonNotRunning}, "", IsolationNone},
		{"named pipe with a path refused", fakeRuntime{info: dockerRootless}, fakeRuntime{}, map[string]string{"DOCKER_HOST": "npipe:////./pipe/../../host/pipe/x"}, [2]Reason{ReasonRemoteEndpoint, ReasonNotRunning}, "", IsolationNone},
		{"upper-case pipe scheme refused", fakeRuntime{info: dockerRootless}, fakeRuntime{}, map[string]string{"DOCKER_HOST": "NPIPE:////./pipe/docker_engine"}, [2]Reason{ReasonRemoteEndpoint, ReasonNotRunning}, "", IsolationNone},
		{"remote pipe context refused", fakeRuntime{context: `"npipe:////server/pipe/docker_engine"`, info: dockerRootless}, fakeRuntime{}, nil, [2]Reason{ReasonRemoteEndpoint, ReasonNotRunning}, "", IsolationNone},
		{"relative unix socket refused", fakeRuntime{info: dockerRootless}, fakeRuntime{}, map[string]string{"DOCKER_HOST": "unix://docker.sock"}, [2]Reason{ReasonRemoteEndpoint, ReasonNotRunning}, "", IsolationNone},
		{"empty unix socket refused", fakeRuntime{info: dockerRootless}, fakeRuntime{}, map[string]string{"DOCKER_HOST": "unix:///"}, [2]Reason{ReasonRemoteEndpoint, ReasonNotRunning}, "", IsolationNone},
		{"local named pipe used", fakeRuntime{info: dockerDesktop}, fakeRuntime{}, map[string]string{"DOCKER_HOST": "npipe:////./pipe/docker_engine"}, [2]Reason{ReasonOK, ReasonNotRunning}, Docker, IsolationVM},
		{"context name is a flag", fakeRuntime{context: desktopCtx, info: dockerRootless}, fakeRuntime{}, map[string]string{"DOCKER_CONTEXT": "--host=tcp://x"}, [2]Reason{ReasonBadContext, ReasonNotRunning}, "", IsolationNone},
		{"daemon down", fakeRuntime{context: desktopCtx}, fakeRuntime{}, nil, [2]Reason{ReasonNotRunning, ReasonNotRunning}, "", IsolationNone},
		{"malformed info", fakeRuntime{context: desktopCtx, info: "{"}, fakeRuntime{info: "not json"}, nil, [2]Reason{ReasonMalformedInfo, ReasonMalformedInfo}, "", IsolationNone},
		{"windows containers", fakeRuntime{context: desktopCtx, info: strings.Replace(dockerDesktop, `"linux"`, `"windows"`, 1)}, fakeRuntime{}, nil, [2]Reason{ReasonNotLinux, ReasonNotRunning}, "", IsolationNone},
		{"seccomp unconfined", fakeRuntime{context: desktopCtx, info: strings.Replace(dockerRootful, "builtin", "unconfined", 1)}, fakeRuntime{}, nil, [2]Reason{ReasonNoSeccomp, ReasonNotRunning}, "", IsolationNone},
		{"no limits", fakeRuntime{context: desktopCtx, info: strings.Replace(dockerRootless, `"PidsLimit":true`, `"PidsLimit":false`, 1)}, fakeRuntime{info: strings.Replace(podmanRootless, `"pids"`, `"io"`, 1)}, nil, [2]Reason{ReasonNoLimits, ReasonNoLimits}, "", IsolationNone},
		{"remote podman refused", fakeRuntime{}, fakeRuntime{info: strings.Replace(podmanRootless, `"serviceIsRemote":false`, `"serviceIsRemote":true`, 1)}, nil, [2]Reason{ReasonNotRunning, ReasonRemoteEndpoint}, "", IsolationNone},
		{"podman without seccomp", fakeRuntime{}, fakeRuntime{info: strings.Replace(podmanRootless, `"seccompEnabled":true`, `"seccompEnabled":false`, 1)}, nil, [2]Reason{ReasonNotRunning, ReasonNoSeccomp}, "", IsolationNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := map[string]fakeRuntime{"docker": tt.docker, "podman": tt.podman}
			bins := map[string]string{"docker": fakeBin(t, "docker"), "podman": fakeBin(t, "podman")}
			p := prober{
				look: func(name string) (string, error) { return bins[name], nil },
				start: func(bin string, _ []string) runFunc {
					return rt[strings.TrimSuffix(filepath.Base(bin), ".exe")].runner(&recorder{})
				},
				os: "linux",
			}
			rep := detect(context.Background(), Env{Repo: t.TempDir(), Getenv: func(k string) string { return tt.env[k] }}, p)
			got := [2]Reason{rep.Checked[0].Reason, rep.Checked[1].Reason}
			if got != tt.want {
				t.Errorf("reasons = %v, want %v", got, tt.want)
			}
			best, ok := rep.Best()
			if ok != (tt.best != "") || best.Runtime != tt.best || (ok && best.Isolation != tt.iso) {
				t.Errorf("best = %+v (%v), want %s %s", best, ok, tt.best, tt.iso)
			}
		})
	}
}

// TestDetectPinsDockerEndpoint checks the endpoint detection found is the
// one the info call used.
func TestDetectPinsDockerEndpoint(t *testing.T) {
	rec := &recorder{}
	bin := fakeBin(t, "docker")
	p := prober{
		look: func(string) (string, error) { return bin, nil },
		start: func(string, []string) runFunc {
			return fakeRuntime{context: `"unix:///run/user/7/docker.sock"`, info: dockerRootless}.runner(rec)
		},
	}
	rep := detect(context.Background(), Env{Repo: t.TempDir(), Getenv: func(k string) string {
		return map[string]string{"DOCKER_CONTEXT": "rootless"}[k]
	}}, p)
	if rep.Checked[0].Host != "unix:///run/user/7/docker.sock" {
		t.Fatalf("host = %q", rep.Checked[0].Host)
	}
	if !slices.Equal(rec.to("context")[0], []string{"context", "inspect", "--format", "{{json .Endpoints.docker.Host}}", "rootless"}) {
		t.Errorf("context call = %q", rec.to("context")[0])
	}
	if rec.to("info")[0][0] != "--host=unix:///run/user/7/docker.sock" {
		t.Errorf("info call = %q", rec.to("info")[0])
	}
}

// TestDetectRefusesPlantedBinary covers the PATH rules: a runtime binary in
// the repository, the current directory or a relative entry never runs.
func TestDetectRefusesPlantedBinary(t *testing.T) {
	repo := t.TempDir()
	planted := filepath.Join(repo, "bin", "docker")
	if runtime.GOOS == "windows" {
		planted += ".exe"
	}
	if err := os.MkdirAll(filepath.Dir(planted), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planted, nil, 0o700); err != nil { //nolint:gosec // G703: in t.TempDir()
		t.Fatal(err)
	}
	cmdShim := filepath.Join(t.TempDir(), "docker.cmd")
	if err := os.WriteFile(cmdShim, nil, 0o700); err != nil { //nolint:gosec // G703: in t.TempDir()
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		found string
		err   error
		want  Reason
	}{
		{"in the repository", planted, nil, ReasonInRepository},
		{"current directory", "docker", exec.ErrDot, ReasonRelativePath},
		{"relative path without ErrDot", filepath.Join("bin", "docker"), nil, ReasonRelativePath},
		{"missing", "", exec.ErrNotFound, ReasonNotFound},
		{"missing file", filepath.Join(t.TempDir(), "gone"), nil, ReasonNotFound},
	}
	if runtime.GOOS == "windows" {
		tests = append(tests, struct {
			name  string
			found string
			err   error
			want  Reason
		}{"cmd shim", cmdShim, nil, ReasonNotExe})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			started := false
			p := prober{
				look:  func(string) (string, error) { return tt.found, tt.err },
				start: func(string, []string) runFunc { started = true; return (&recorder{}).run },
			}
			st := p.check(context.Background(), Docker, Env{Repo: repo, Getenv: func(string) string { return "" }})
			if st.Reason != tt.want || started || st.Usable() {
				t.Errorf("reason %s (want %s), started %v", st.Reason, tt.want, started)
			}
		})
	}
}

func TestDetectPrefersConfiguredRuntime(t *testing.T) {
	p := prober{look: func(string) (string, error) { return "", errors.New("none") }}
	rep := detect(context.Background(), Env{Preferred: Podman, Getenv: func(string) string { return "" }}, p)
	if rep.Checked[0].Runtime != Podman || rep.Checked[1].Runtime != Docker {
		t.Errorf("order = %v", rep.Checked)
	}
	if _, ok := rep.Best(); ok {
		t.Error("no runtime on PATH, yet one is usable")
	}
}

// TestPodmanRemoteRefusedWithoutRunning: a Podman that would be a client
// of a service elsewhere is refused before it starts, and a local one is
// always asked with --remote=false.
func TestPodmanRemoteRefusedWithoutRunning(t *testing.T) {
	tests := []struct {
		name string
		goos string
		env  map[string]string
		want Reason
	}{
		{"CONTAINER_HOST set", "linux", map[string]string{"CONTAINER_HOST": "ssh://me@build.example/run/podman/podman.sock"}, ReasonRemoteEndpoint},
		{"CONTAINER_CONNECTION set", "linux", map[string]string{"CONTAINER_CONNECTION": "buildhost"}, ReasonRemoteEndpoint},
		{"podman machine on Windows", "windows", nil, ReasonRemoteEndpoint},
		{"podman machine on macOS", "darwin", nil, ReasonRemoteEndpoint},
		{"local podman", "linux", nil, ReasonOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{}
			bin := fakeBin(t, "podman")
			p := prober{
				look:  func(string) (string, error) { return bin, nil },
				start: func(string, []string) runFunc { return fakeRuntime{info: podmanRootless}.runner(rec) },
				os:    tt.goos,
			}
			st := p.check(context.Background(), Podman, Env{Repo: t.TempDir(), Getenv: func(k string) string { return tt.env[k] }})
			if st.Reason != tt.want {
				t.Fatalf("reason %s, want %s", st.Reason, tt.want)
			}
			if tt.want != ReasonOK && len(rec.calls) != 0 {
				t.Errorf("podman ran: %q", rec.calls)
			}
			if tt.want == ReasonOK && (len(rec.calls) != 1 || rec.calls[0][0] != "--remote=false") {
				t.Errorf("info not pinned local: %q", rec.calls)
			}
		})
	}
}
