package scanrun

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as a fake scanner. installFake copies it into a
// directory named after a mode; started with a scanner's first argument
// ("detect" or "scan"), TestMain runs fakeMain instead of the tests. The
// runner passes no environment of its own, so the mode travels in the path.

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && (os.Args[1] == "detect" || os.Args[1] == "scan") {
		os.Exit(fakeMain(filepath.Base(filepath.Dir(os.Args[0])), os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeMain checks what every run must look like, then acts out mode.
func fakeMain(mode string, args []string) int {
	if os.Getenv("FAKE_GRANDCHILD") != "" {
		return grandchild()
	}
	marker := filepath.Join(filepath.Dir(os.Args[0]), "ran")
	_ = os.WriteFile(marker, nil, 0o600) //nolint:gosec // G703: beside the fake, in t.TempDir()
	if why := checkSandbox(args); why != "" {
		fmt.Fprintln(os.Stderr, why)
		return 42
	}
	report, repo := reportArgs(args)
	switch mode {
	case "findings":
		return writeFindings(args[0], report, repo)
	case "empty":
		return 128
	case "malformed":
		writeReport(report, []byte("{not json"))
	case "huge":
		writeReport(report, []byte("["+strings.Repeat(" ", 4096)+"]"))
	case "outside":
		writeReport(report, gitleaksJSON(filepath.Join(filepath.Dir(repo), "elsewhere", "k.py")))
	case "slow":
		time.Sleep(time.Minute)
	case "tree":
		startGrandchild(args)
		time.Sleep(time.Minute)
	case "exit3":
		return 3
	case "noreport":
	}
	return 0
}

// checkSandbox fails the run unless creep's environment and offline flags
// were applied: no key, proxies at the black hole, empty PATH, a fresh
// HOME beside a working directory that is not the repository.
func checkSandbox(args []string) string {
	wd, _ := os.Getwd()
	_, repo := reportArgs(args)
	switch {
	case os.Getenv("CREEP_API_KEY") != "":
		return "CREEP_API_KEY leaked"
	case os.Getenv("HTTPS_PROXY") != blackholeProxy || os.Getenv("https_proxy") != blackholeProxy:
		return "proxy not pinned"
	case os.Getenv("PATH") != "":
		return "PATH leaked"
	case filepath.Dir(os.Getenv("HOME")) != filepath.Dir(wd) || wd == repo:
		return "HOME or cwd not in the workspace"
	case args[0] == "detect" && !hasAll(args, "--no-git", "--redact", "--config", "--gitleaks-ignore-path"):
		return "gitleaks offline flags missing"
	case args[0] == "scan" && (!hasAll(args, "--offline", "--no-ignore", "--config") || os.Getenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY") == ""):
		return "osv-scanner offline flags missing"
	}
	return ""
}

func hasAll(args []string, want ...string) bool {
	for _, w := range want {
		if !slices.Contains(args, w) {
			return false
		}
	}
	return true
}

// reportArgs finds the report path and the repository in either tool's
// argument list.
func reportArgs(args []string) (report, repo string) {
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "--report-path", "--output":
			report = args[i+1]
		case "--source":
			repo = args[i+1]
		}
	}
	if args[0] == "scan" {
		repo = args[len(args)-1]
	}
	return report, repo
}

func writeFindings(cmd, report, repo string) int {
	if cmd == "detect" {
		writeReport(report, gitleaksJSON(filepath.Join(repo, "app", "config.py")))
		return 0
	}
	lock := filepath.Join(repo, "package-lock.json")
	data := fmt.Sprintf(`{"results":[{"source":{"path":%q,"type":"lockfile"},"packages":[`+
		`{"package":{"name":"lodash","version":"4.17.15","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-p6mc-m468-83gw","details":"x"},{"id":"GHSA-35jh-r3h4-6jhm"}]}]}]}`, lock)
	writeReport(report, []byte(data))
	return 1 // osv-scanner: advisories found
}

// gitleaksJSON is a redacted gitleaks report: two rules on one line, the
// first repeated, so the runner must deduplicate.
func gitleaksJSON(file string) []byte {
	one := fmt.Sprintf(`{"File":%q,"StartLine":3,"RuleID":"generic-api-key","Secret":"REDACTED","Match":"REDACTED"}`, file)
	two := fmt.Sprintf(`{"File":%q,"StartLine":3,"RuleID":"aws-access-token","Secret":"REDACTED"}`, file)
	return []byte("[" + one + "," + one + "," + two + "]")
}

// installFake places a copy of the test binary at dir/mode/<scanner> and
// returns its path.
func installFake(t *testing.T, dir, mode, scanner string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		scanner += ".exe"
	}
	bin := filepath.Join(dir, mode, scanner)
	if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Link(self, bin) == nil {
		return bin
	}
	copyFile(t, self, bin)
	return bin
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	in, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700) //nolint:gosec // G302: a fake executable in t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// ran reports whether the fake at bin was started.
func ran(bin string) bool {
	_, err := os.Stat(filepath.Join(filepath.Dir(bin), "ran"))
	return err == nil
}

// startGrandchild starts a helper the way a tool might, then leaves it
// running. It marks itself started, and survived if no one killed it.
func startGrandchild(args []string) {
	cmd := exec.Command(os.Args[0], args...) //nolint:gosec // G204: the test binary itself
	cmd.Env = append(os.Environ(), "FAKE_GRANDCHILD=1")
	_ = cmd.Start()
	for range 100 { // wait until it runs, so the timeout cannot win the race
		if _, err := os.Stat(treeMarker("started")); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func grandchild() int {
	writeReport(treeMarker("started"), nil)
	time.Sleep(2 * time.Second)
	writeReport(treeMarker("survived"), nil)
	return 0
}

func treeMarker(name string) string { return filepath.Join(filepath.Dir(os.Args[0]), name) }

// writeReport writes the fake's report where the runner asked for it.
func writeReport(path string, data []byte) {
	_ = os.WriteFile(path, data, 0o600) //nolint:gosec // G703: the runner's report path in its temporary directory
}
