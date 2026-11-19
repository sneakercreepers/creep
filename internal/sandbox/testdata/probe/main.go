// Command probe runs inside a sandbox container in the integration test and
// reports, from the inside, whether the hardened profile holds. It is built
// for Linux by the test and imported as the only file of a local image.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "sleep" {
		time.Sleep(10 * time.Minute)
		return
	}
	problems := check()
	if len(problems) > 0 {
		fmt.Println(strings.Join(problems, "; "))
		os.Exit(1)
	}
	fmt.Print("ok")
}

func check() []string {
	var p []string
	if os.Getuid() != 65534 || os.Getgid() != 65534 {
		p = append(p, fmt.Sprintf("uid %d gid %d", os.Getuid(), os.Getgid()))
	}
	status, _ := os.ReadFile("/proc/self/status")
	for _, want := range []string{"CapEff:\t0000000000000000", "CapPrm:\t0000000000000000", "CapBnd:\t0000000000000000", "NoNewPrivs:\t1", "Seccomp:\t2"} {
		if !strings.Contains(string(status), want) {
			p = append(p, "missing "+strings.ReplaceAll(want, "\t", " "))
		}
	}
	if os.WriteFile("/probe-write", []byte("x"), 0o600) == nil {
		p = append(p, "root file system is writable")
	}
	if os.WriteFile("/tmp/x", []byte("x"), 0o600) != nil {
		p = append(p, "/tmp is not writable")
	}
	p = append(p, network()...)
	p = append(p, files()...)
	p = append(p, limits()...)
	return p
}

// network allows the loopback interface only.
func network() []string {
	dev, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return []string{"no /proc/net/dev"}
	}
	var p []string
	for _, line := range strings.Split(string(dev), "\n")[2:] {
		name, _, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && name != "lo" {
			p = append(p, "network interface "+name)
		}
	}
	return p
}

func files() []string {
	var p []string
	env, err := os.ReadFile("/app/.env")
	if err != nil || !strings.HasPrefix(string(env), "SECRET_KEY=creep-synthetic-") {
		p = append(p, "synthetic .env missing")
	}
	if os.WriteFile("/app/.env", []byte("x"), 0o600) == nil {
		p = append(p, "mount is writable")
	}
	p = append(p, environment()...)
	for _, sock := range []string{"/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock"} {
		if _, err := os.Stat(sock); err == nil {
			p = append(p, sock+" is mounted")
		}
	}
	return p
}

// runtimeVars are the variables a runtime sets itself; proxyVars must be
// present only empty. Anything else came from somewhere it should not.
var (
	runtimeVars = map[string]bool{"PATH": true, "HOSTNAME": true, "HOME": true, "TERM": true, "container": true}
	proxyVars   = []string{"HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "NO_PROXY", "ALL_PROXY"}
)

// environment allows exactly the spec's APP_ENV, the runtime's own
// variables and empty proxy variables.
func environment() []string {
	var p []string
	if os.Getenv("APP_ENV") != "test" {
		p = append(p, "APP_ENV missing")
	}
	for _, kv := range os.Environ() {
		name, value, _ := strings.Cut(kv, "=")
		switch {
		case isProxy(name) && value != "":
			p = append(p, "proxy variable "+name+" is set")
		case isProxy(name), runtimeVars[name], name == "APP_ENV":
		default:
			p = append(p, "unexpected variable "+name)
		}
	}
	return p
}

func isProxy(name string) bool {
	for _, v := range proxyVars {
		if strings.EqualFold(v, name) {
			return true
		}
	}
	return false
}

// limit is one cgroup limit: the cgroup v2 file, then the v1 file, and the
// value both hold for the profile.
type limit struct{ v2, v1, want string }

var limitFiles = []limit{
	{"/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/pids/pids.max", "128"},
	{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes", "536870912"},
	{"/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "100000"},
}

// limits fails when a limit is wrong or cannot be read at all.
func limits() []string {
	var p []string
	for _, l := range limitFiles {
		got, err := os.ReadFile(l.v2)
		if err != nil {
			got, err = os.ReadFile(l.v1)
		}
		value := strings.Fields(strings.TrimSpace(string(got)))
		switch {
		case err != nil:
			p = append(p, "cannot read "+l.v2+" or "+l.v1)
		case len(value) == 0 || value[0] != l.want:
			p = append(p, fmt.Sprintf("%s = %q, want %s", l.v2, got, l.want))
		}
	}
	return p
}
