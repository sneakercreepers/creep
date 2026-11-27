package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMountRefusesHostPaths is the protection test for mounts: the runtime
// socket, host credential paths, links out of the work directory and
// anything that is not a regular file creep wrote never reach a container.
func TestMountRefusesHostPaths(t *testing.T) {
	rec := &recorder{}
	s := testSandbox(t, rec)
	home, _ := os.UserHomeDir()
	inWork := func(rel string, dir bool) string {
		p := filepath.Join(s.work, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if dir {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			return p
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		source string
		want   error
	}{
		{"docker socket", "/var/run/docker.sock", ErrHostPath},
		{"rootless docker socket", "/run/user/1000/docker.sock", ErrHostPath},
		{"windows docker pipe", `\\.\pipe\docker_engine`, ErrHostPath},
		{"podman socket", "/run/user/1000/podman/podman.sock", ErrHostPath},
		{"socket-named file in the work directory", inWork("docker.sock", false), ErrHostPath},
		{"ssh keys", filepath.Join(home, ".ssh", "id_ed25519"), ErrHostPath},
		{"aws credentials", filepath.Join(home, ".aws", "credentials"), ErrHostPath},
		{"docker config", filepath.Join(home, ".docker", "config.json"), ErrHostPath},
		{"kube config", filepath.Join(home, ".kube", "config"), ErrHostPath},
		{"git credentials", filepath.Join(home, ".git-credentials"), ErrHostPath},
		{"creep state", filepath.Join(home, ".config", "creep", "state.key"), ErrHostPath},
		{"credential name in the work directory", inWork(".aws/credentials", false), ErrHostPath},
		{"file outside the work directory", outside, ErrOutsideWorkdir},
		{"the host root", string(filepath.Separator), ErrOutsideWorkdir},
		{"a directory", inWork("dir", true), ErrHostPath},
		{"the work directory itself", s.work, ErrOutsideWorkdir},
	}
	if link := filepath.Join(s.work, "link"); os.Symlink(outside, link) == nil {
		tests = append(tests, struct {
			name   string
			source string
			want   error
		}{"link out of the work directory", link, ErrOutsideWorkdir})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.Run(context.Background(), Spec{Image: testImage, Mounts: []Mount{{Source: tt.source, Target: "/app/x"}}})
			if err == nil || (tt.want != nil && !errors.Is(err, tt.want) && !errors.Is(err, os.ErrNotExist)) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	if n := len(rec.to("run")); n != 0 {
		t.Errorf("%d containers started with a refused mount", n)
	}
}

func TestMountTargets(t *testing.T) {
	s := testSandbox(t, &recorder{})
	env, err := s.writeEnvFile(map[string]string{"API_KEY": "creep-synthetic-test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"", "app/.env", "/", "/proc/self", "/sys", "/dev/x", "/tmp/x", "/a/../b", "/a,readonly=false", "/a\nb"} {
		if _, err := s.runArgs("creep-x-1", Spec{Image: testImage, Mounts: []Mount{{Source: env, Target: target}}}); !errors.Is(err, ErrSpec) {
			t.Errorf("target %q: %v", target, err)
		}
	}
	args, err := s.runArgs("creep-x-1", Spec{Image: testImage, Mounts: []Mount{{Source: env, Target: "/app/.env"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := ",target=/app/.env,readonly"
	if !strings.HasSuffix(args[len(args)-2], want) {
		t.Errorf("mount arg %q", args[len(args)-2])
	}
}
