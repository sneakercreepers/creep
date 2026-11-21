package gateway

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeCLIEnv switches the test binary into a fake model CLI: the
// re-exec helper pattern, so no real model, shell or network is involved.
const fakeCLIEnv = "CREEP_FAKE_CLI"

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeCLIEnv); mode != "" {
		os.Exit(fakeCLI(mode))
	}
	os.Exit(runWithPrivateCache(m))
}

// runWithPrivateCache keeps model run directories out of the developer's
// own cache directory while the tests run.
func runWithPrivateCache(m *testing.M) int {
	cache, err := os.MkdirTemp("", "creep-gateway-cache-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(cache)
	// The walk up from the run directory stops at "home", so it never reaches
	// the system temp directory, which is world-writable on Linux.
	userCacheDir = func() (string, error) { return cache, nil }
	userHomeDir = userCacheDir
	return m.Run()
}

// fakeCLI behaves like one kind of model CLI, reading the prompt on stdin.
func fakeCLI(mode string) int {
	in, _ := io.ReadAll(os.Stdin)
	switch mode {
	case "echo":
		os.Stdout.Write(in)
	case "env":
		fmt.Print(strings.Join(os.Environ(), "\n"))
	case "cwd":
		wd, _ := os.Getwd()
		entries, _ := os.ReadDir(".")
		fmt.Printf("%s\n%d", wd, len(entries))
	case "walkup":
		printFilesAbove()
	case "geminilookup":
		printGeminiLookup()
	case "touch":
		_ = os.WriteFile("creep-canary.txt", []byte("hi"), 0o600)
		fmt.Print(`{"ok":true}`)
	case "tmpfile":
		_ = os.WriteFile(os.Getenv("TMPDIR")+string(os.PathSeparator)+"cache", []byte("x"), 0o600) //nolint:gosec // G703: the gateway sets TMPDIR
		fmt.Print(`{"ok":true}`)
	case "huge":
		chunk := bytes.Repeat([]byte("A"), 64<<10)
		for {
			if _, err := os.Stdout.Write(chunk); err != nil {
				return 1
			}
		}
	case "sleep":
		time.Sleep(time.Minute)
	case "drip":
		for {
			os.Stdout.Write([]byte("{"))
			time.Sleep(50 * time.Millisecond)
		}
	case "exit3":
		fmt.Fprint(os.Stderr, "secret prompt echo")
		return 3
	case "spawn", "spawnhang":
		startLateWriter()
		fmt.Print(`{"ok":true}`)
		if mode == "spawnhang" {
			time.Sleep(time.Minute)
		}
	case "late":
		time.Sleep(6 * time.Second) // past -race builds' 1 s exit delay and a slow taskkill on Windows
		_ = os.WriteFile("late.txt", []byte("x"), 0o600)
		_ = os.WriteFile(os.Getenv(fakeMarkEnv), []byte("x"), 0o600) //nolint:gosec // G703: the test sets this path in t.TempDir()
	}
	return 0
}

// fakeMarkEnv names the file a late writer creates outside its working
// directory, so a test can see whether it outlived the run.
const fakeMarkEnv = "CREEP_FAKE_MARK"

// startLateWriter starts a detached background child that writes after
// its parent has exited, like a CLI helper process left behind.
func startLateWriter() {
	child := exec.Command(os.Args[0]) //nolint:gosec // G204: this test binary
	child.Env = append(os.Environ(), fakeCLIEnv+"=late")
	_ = child.Start()
}

// fakeCommand returns a Command that re-runs this test binary in mode.
func fakeCommand(t *testing.T, mode string, timeout time.Duration) *Command {
	t.Helper()
	c, err := NewCommand(fakeOptions(t, mode, timeout))
	if err != nil {
		t.Fatalf("NewCommand: %v", err)
	}
	return c
}

func fakeOptions(t *testing.T, mode string, timeout time.Duration) CommandOptions {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{fakeCLIEnv: mode, "PATH": os.Getenv("PATH"), "SystemRoot": os.Getenv("SystemRoot"), "AWS_SECRET_ACCESS_KEY": "do-not-pass"}
	return CommandOptions{
		Run:            "'" + self + "' -p --tools \"\"",
		Env:            []string{fakeCLIEnv},
		Getenv:         func(k string) string { return env[k] },
		Timeout:        timeout,
		MaxOutputBytes: 1 << 20,
	}
}

// printFilesAbove prints the working directory, then every file in it or a
// parent that a model CLI reads from above its working directory (Gemini
// CLI: .env, .gemini/.env, GEMINI.md; Codex: AGENTS.md).
func printFilesAbove() {
	dir, _ := os.Getwd()
	fmt.Println(dir)
	for {
		for _, name := range []string{".env", filepath.Join(".gemini", ".env"), "GEMINI.md", "AGENTS.md"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				fmt.Println(filepath.Join(dir, name))
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}
		dir = parent
	}
}

// printGeminiLookup mirrors Gemini CLI's upward searches from the working
// directory (packages/cli/src/config/settings.ts findEnvFile, with
// ignoreLocalEnv off; packages/core/src/utils/memoryDiscovery.ts
// findProjectRoot) and prints, one per line: the env file a trusted run
// loads, the one an untrusted run loads, and the GEMINI.md ceiling.
func printGeminiLookup() {
	wd, _ := os.Getwd()
	fmt.Println(firstUp(wd, filepath.Join(".gemini", ".env"), ".env"))
	fmt.Println(firstUp(wd, ".env"))
	fmt.Println(filepath.Dir(firstUp(wd, ".git")))
}

// firstUp returns the first path dir/name that exists, trying each name in
// order in each directory from dir up to the volume root, or "".
func firstUp(dir string, names ...string) string {
	for {
		for _, name := range names {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return filepath.Join(dir, name)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
