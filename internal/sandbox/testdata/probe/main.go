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
	if os.Getenv("APP_ENV") != "test" || os.Getenv("CREEP_API_KEY") != "" {
		p = append(p, "environment is not the synthetic one")
	}
	for _, sock := range []string{"/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock"} {
		if _, err := os.Stat(sock); err == nil {
			p = append(p, sock+" is mounted")
		}
	}
	return p
}

// limits reads cgroup v2 limits when the file system shows them.
func limits() []string {
	want := map[string]string{"/sys/fs/cgroup/pids.max": "128", "/sys/fs/cgroup/memory.max": "536870912"}
	var p []string
	for file, value := range want {
		got, err := os.ReadFile(file)
		if err == nil && strings.TrimSpace(string(got)) != value {
			p = append(p, fmt.Sprintf("%s = %s", file, strings.TrimSpace(string(got))))
		}
	}
	return p
}
