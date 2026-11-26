package releasescripts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	script    = "../../../.github/scripts/package-repos.sh"
	downloads = "https://github.com/sneakercreepers/creep/releases/download/"
	caskPath  = "homebrew/Casks/creep.rb"
	scoopPath = "scoop/creep.json"
)

// fakeGH logs every call and answers like the GitHub contents API: a file
// named by FAKE_TAP or FAKE_BUCKET exists, any other path is a 404. Like
// the real gh (v0.5.0 release run), a 404 prints the error body on stdout,
// even with --jq, and exits 1.
const fakeGH = `#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
case "$*" in *"-X PUT"*) echo https://github.invalid/commit; exit 0 ;; esac
case "$*" in *homebrew-tap*) f="${FAKE_TAP:-}" ;; *) f="${FAKE_BUCKET:-}" ;; esac
if [ -z "$f" ]; then
  echo '{"message":"Not Found","status":"404"}'
  echo "gh: Not Found (HTTP 404)" >&2
  exit 1
fi
case "$*" in *"--jq .sha"*) echo "sha-$(basename "$f")" ;; *) cat "$f" ;; esac
`

var archives = []string{"darwin_amd64.tar.gz", "darwin_arm64.tar.gz", "linux_amd64.tar.gz", "linux_arm64.tar.gz", "windows_amd64.zip", "windows_arm64.zip"}

func sum(name string) string {
	h := sha256.Sum256([]byte(name))
	return hex.EncodeToString(h[:])
}

// writeDist writes what goreleaser renders for tag: checksums.txt, a cask
// (sha256 before url, #{version} in the url) and a manifest (url before hash).
func writeDist(t *testing.T, dir, tag string) {
	t.Helper()
	version := strings.TrimPrefix(tag, "v")
	var sums, cask, scoop strings.Builder
	fmt.Fprintf(&cask, "cask \"creep\" do\n  version %q\n", version)
	fmt.Fprintf(&scoop, "{\n    \"version\": %q,\n    \"architecture\": {\n", version)
	for _, a := range archives {
		name := "creep_" + version + "_" + a
		fmt.Fprintf(&sums, "%s  %s\n", sum(name), name)
		if strings.HasPrefix(a, "windows") {
			fmt.Fprintf(&scoop, "        %q: {\n            \"url\": \"%s%s/%s\",\n            \"hash\": %q\n        },\n", a, downloads, tag, name, sum(name))
			continue
		}
		fmt.Fprintf(&cask, "    on_arm do\n      sha256 %q\n      url \"%s%s/creep_#{version}_%s\"\n    end\n", sum(name), downloads, tag, a)
	}
	cask.WriteString("  postflight_steps do\n  end\nend\n")
	scoop.WriteString("    }\n}\n")
	mustWrite(t, filepath.Join(dir, "checksums.txt"), sums.String())
	mustWrite(t, filepath.Join(dir, caskPath), cask.String())
	mustWrite(t, filepath.Join(dir, scoopPath), scoop.String())
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil { //nolint:gosec // G703: paths under t.TempDir()
		t.Fatal(err)
	}
}

func replaceIn(t *testing.T, path, old, repl string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: files the test wrote
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), old) {
		t.Fatalf("%s lacks %q", path, old)
	}
	mustWrite(t, path, strings.Replace(string(data), old, repl, 1))
}

// remote writes the file a repository already holds: the dist/ file of
// another release, or the same file as dist/ when tag is "same".
func remote(t *testing.T, dist, tag, path string) string {
	t.Helper()
	dir := t.TempDir()
	if tag == "same" {
		data, err := os.ReadFile(filepath.Join(dist, path)) //nolint:gosec // G304: files the test wrote
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(dir, path), string(data))
		return filepath.Join(dir, path)
	}
	writeDist(t, dir, tag)
	return filepath.Join(dir, path)
}

type run struct {
	code  int
	out   string
	calls string
}

// runScript runs package-repos.sh under bash with the fake gh first on PATH.
func runScript(t *testing.T, env map[string]string, args ...string) run {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the release workflow runs on Linux runners; CI tests its scripts on Linux")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	bin, logDir := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fakeGH), 0o700); err != nil { //nolint:gosec // G306: the fake must be executable
		t.Fatal(err)
	}
	path, err := filepath.Abs(script)
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(logDir, "gh-calls")
	cmd := exec.Command(bash, append([]string{path}, args...)...) //nolint:gosec // G204: the script under test, by fixed name
	cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + logDir, "GH_LOG=" + log}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	r := run{out: string(out)}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		r.code = exit.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	if data, err := os.ReadFile(log); err == nil { //nolint:gosec // G304: the fake's own log
		r.calls = string(data)
	}
	return r
}
