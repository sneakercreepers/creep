package sandbox

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as a fake docker CLI. installFake copies it into
// a directory named after a mode as docker(.exe); started under that name,
// TestMain runs fakeMain instead of the tests. The runner passes only its
// own fixed environment, so the mode travels in the path.

const fakeID = "0123456789ab0123456789ab0123456789ab0123456789ab0123456789abcdef"

func TestMain(m *testing.M) {
	if strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") == "docker" {
		os.Exit(fakeMain(filepath.Base(filepath.Dir(os.Args[0])), os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeMain logs its arguments beside itself, fails unless the environment
// is creep's, then answers like a rootless Docker.
func fakeMain(mode string, args []string) int {
	logCall(args)
	if why := checkEnv(); why != "" {
		fmt.Println(why)
		return 42
	}
	if why := checkRunConfig(args); why != "" {
		fmt.Println(why)
		return 42
	}
	switch mode {
	case "flood":
		_, _ = io.WriteString(os.Stdout, strings.Repeat("x", 3<<20))
		return 0
	case "slow":
		time.Sleep(time.Minute)
		return 0
	}
	return answer(args)
}

func answer(args []string) int {
	sub := subcommand(args)
	switch sub {
	case "context":
		fmt.Println(`"unix:///run/user/1000/docker.sock"`)
	case "info":
		fmt.Println(`{"OSType":"linux","OperatingSystem":"Ubuntu","SecurityOptions":["name=seccomp,profile=builtin","name=rootless","name=cgroupns"],"MemoryLimit":true,"PidsLimit":true,"CPUShares":true}`)
	case "ps":
		fmt.Println(fakeID)
	case "image":
		fmt.Println("null")
	case "run":
		fmt.Print("poc output")
		return 3
	}
	return 0
}

func subcommand(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// checkEnv fails the call when creep's environment leaked anything.
func checkEnv() string {
	wd, _ := os.Getwd()
	switch {
	case os.Getenv("CREEP_API_KEY") != "":
		return "CREEP_API_KEY leaked"
	case os.Getenv("DOCKER_HOST") != "":
		return "DOCKER_HOST leaked"
	case os.Getenv("HTTPS_PROXY") != "" || os.Getenv("https_proxy") != "":
		return "proxy leaked"
	case os.Getenv("GITHUB_TOKEN") != "":
		return "token leaked"
	case strings.Contains(os.Getenv("PATH"), "planted-repo"):
		return "repository PATH entry leaked"
	case strings.Contains(wd, "planted-repo"):
		return "working directory is the repository"
	}
	return ""
}

// checkRunConfig fails a run unless DOCKER_CONFIG is an empty directory:
// a real docker would add the proxies of any config.json it finds there
// to the container's environment.
func checkRunConfig(args []string) string {
	if subcommand(args) != "run" {
		return ""
	}
	dir := os.Getenv("DOCKER_CONFIG")
	entries, err := os.ReadDir(dir)
	if dir == "" || err != nil || len(entries) != 0 {
		return "run reads the operator's docker config"
	}
	return ""
}

func logCall(args []string) {
	f, err := os.OpenFile(filepath.Join(filepath.Dir(os.Args[0]), "calls.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G703: beside the fake, in t.TempDir()
	if err != nil {
		return
	}
	defer f.Close()
	line, _ := json.Marshal(args)
	_, _ = f.Write(append(line, '\n'))
}

// installFake copies the test binary to <tmp>/<mode>/docker(.exe).
func installFake(t *testing.T, mode string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), mode)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "docker"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, name)
	if err := os.WriteFile(bin, data, 0o700); err != nil { //nolint:gosec // G703: in t.TempDir()
		t.Fatal(err)
	}
	return bin
}

// fakeCalls reads every argv the fake was started with.
func fakeCalls(t *testing.T, bin string) [][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(filepath.Dir(bin), "calls.log"))
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var args []string
		if err := json.Unmarshal([]byte(line), &args); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, args)
	}
	return calls
}

// callsTo filters calls by subcommand.
func callsTo(calls [][]string, sub string) [][]string {
	var out [][]string
	for _, c := range calls {
		if subcommand(c) == sub {
			out = append(out, c)
		}
	}
	return out
}

// hostileEnv is an operator environment full of things the CLI must not
// see, with PATH pointing into a planted repository first.
func hostileEnv(t *testing.T, fakeDir string) (func(string) string, string) {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "planted-repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"PATH":          strings.Join([]string{repo, "relative/bin", fakeDir}, string(filepath.ListSeparator)),
		"CREEP_API_KEY": "sk-secret", "GITHUB_TOKEN": "ghp_x", "HTTPS_PROXY": "http://evil:8080",
		"DOCKER_HOST": "", "HOME": t.TempDir(), "DOCKER_CONFIG": proxiedDockerConfig(t),
	}
	if runtime.GOOS != "windows" {
		vars["TMPDIR"] = os.TempDir()
	}
	return func(k string) string { return vars[k] }, repo
}

// proxyConfig is a Docker client config whose proxies a real docker run
// would add to the container, password included.
const proxyConfig = `{"proxies":{"default":{"httpProxy":"http://user:hunter2@proxy.example:3128","httpsProxy":"http://user:hunter2@proxy.example:3128","noProxy":"internal.example"}}}` //nolint:gosec // G101: a fake proxy password the test proves never reaches a container

// proxiedDockerConfig is an operator DOCKER_CONFIG directory holding
// proxyConfig.
func proxiedDockerConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(proxyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}
