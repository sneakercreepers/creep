package actionscripts

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRoot is the module root, seen from this package's directory.
const repoRoot = "../../.."

// result is one script run: its exit code, combined output and the
// key=value lines it wrote to $GITHUB_OUTPUT.
type result struct {
	code    int
	out     string
	outputs map[string]string
}

// sandbox is one test's runner: a fake bin directory first on PATH, a
// RUNNER_TEMP and a working directory.
type sandbox struct {
	t       *testing.T
	bin     string
	temp    string
	workdir string
	env     map[string]string
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the Action runs on Linux and macOS runners; CI tests its scripts on Linux")
	}
	return &sandbox{t: t, bin: t.TempDir(), temp: t.TempDir(), workdir: t.TempDir(), env: map[string]string{}}
}

// fake installs a bash program named name on the sandbox PATH.
func (s *sandbox) fake(name, body string) {
	s.t.Helper()
	mustWrite(s.t, filepath.Join(s.bin, name), "#!/usr/bin/env bash\nset -u\n"+body, 0o755)
}

func (s *sandbox) run(script string) result {
	s.t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		s.t.Skip("bash not installed")
	}
	path, err := filepath.Abs(filepath.Join(repoRoot, "action", script))
	if err != nil {
		s.t.Fatal(err)
	}
	output := filepath.Join(s.t.TempDir(), "github_output")
	mustWrite(s.t, output, "", 0o600)
	cmd := exec.Command(bash, path) //nolint:gosec // G204: the scripts under test, by fixed name
	cmd.Dir = s.workdir
	cmd.Env = []string{
		"PATH=" + s.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + s.temp, "GITHUB_OUTPUT=" + output, "RUNNER_TEMP=" + s.temp,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
	}
	for k, v := range s.env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	r := result{out: string(out), outputs: readOutputs(s.t, output)}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		r.code = exit.ExitCode()
	case err != nil:
		s.t.Fatal(err)
	}
	return r
}

func readOutputs(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: the test's own output file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	outputs := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			t.Fatalf("GITHUB_OUTPUT line without '=': %q", sc.Text())
		}
		if _, dup := outputs[k]; dup {
			t.Fatalf("GITHUB_OUTPUT sets %s twice", k)
		}
		outputs[k] = v
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return outputs
}

func mustWrite(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: files the test wrote
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// git runs git in dir with no user or system config.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@invalid", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func wantCode(t *testing.T, r result, code int, want string) {
	t.Helper()
	if r.code != code {
		t.Fatalf("exit %d, want %d\n%s", r.code, code, r.out)
	}
	if !strings.Contains(r.out, want) {
		t.Fatalf("output lacks %q:\n%s", want, r.out)
	}
}
