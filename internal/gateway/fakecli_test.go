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
	userCacheDir = func() (string, error) { return cache, nil }
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
		time.Sleep(3 * time.Second) // past -race builds' 1 s exit delay
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
