package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sneakercreepers/creep/internal/repofile"
)

// cliResult is one finished runtime CLI call.
type cliResult struct {
	stdout    []byte
	exit      int
	truncated bool // stdout passed the call's limit; the rest was dropped
}

// runFunc runs the runtime CLI with args, keeping at most limit bytes of
// stdout. A non-zero exit is a result, not an error; an error means the
// CLI did not start or ctx ended.
type runFunc func(ctx context.Context, args []string, limit int) (cliResult, error)

// waitDelay bounds how long a child holding stdout open can delay a run
// after the CLI itself was killed.
const waitDelay = 2 * time.Second

// newExecRunner runs bin with a fixed environment, no stdin, stderr to the
// null device and a working directory outside the repository.
func newExecRunner(bin string, env []string) runFunc {
	return func(ctx context.Context, args []string, limit int) (cliResult, error) {
		// G204: bin is the runtime's final path outside the repository and
		// args come only from this package's fixed builders (ADR 0016).
		cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204, see above
		out := &cappedBuffer{limit: limit}
		cmd.Env, cmd.Dir, cmd.Stdout, cmd.WaitDelay = env, os.TempDir(), out, waitDelay
		err := cmd.Run()
		if ctx.Err() != nil {
			return cliResult{}, fmt.Errorf("%s %s: %w", filepath.Base(bin), args[0], context.Cause(ctx))
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return cliResult{stdout: out.data, exit: exit.ExitCode(), truncated: out.over}, nil
		}
		if err != nil {
			return cliResult{}, fmt.Errorf("start %s: %w", filepath.Base(bin), err)
		}
		return cliResult{stdout: out.data, truncated: out.over}, nil
	}
}

// cappedBuffer keeps the first limit bytes and drains the rest, so a
// flooding container cannot fill memory or block the CLI.
type cappedBuffer struct {
	data  []byte
	limit int
	over  bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	room := b.limit - len(b.data)
	if len(p) > room {
		b.over = true
		b.data = append(b.data, p[:max(room, 0)]...)
		return len(p), nil
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

// passedEnv lists the variables the runtime CLI may inherit: where its own
// config and rootless state live, and what Windows needs to start a
// program. DOCKER_HOST is not passed (the endpoint goes as --host), and
// neither are proxies, tokens or CREEP_API_KEY.
var passedEnv = []string{
	"HOME", "USERPROFILE", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
	"DBUS_SESSION_BUS_ADDRESS", "DOCKER_CONFIG",
	"SYSTEMROOT", "SystemDrive", "APPDATA", "LOCALAPPDATA", "ProgramData", "ProgramFiles",
	"TEMP", "TMP", "TMPDIR",
}

// runtimeEnv is the CLI's whole environment.
func runtimeEnv(getenv func(string) string, repo string) []string {
	env := []string{"PATH=" + safePath(getenv("PATH"), repo), "DOCKER_CLI_HINTS=false", "LC_ALL=C"}
	for _, name := range passedEnv {
		if v := getenv(name); v != "" && !strings.ContainsRune(v, 0) {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// safePath keeps the absolute PATH entries outside the repository and the
// working directory: Podman finds helpers such as conmon on PATH, and none
// may come from the scanned code.
func safePath(path, repo string) string {
	var keep []string
	for _, dir := range filepath.SplitList(path) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		if _, ok := repofile.OutsideRepo(dir, repo); ok {
			keep = append(keep, dir)
		}
	}
	return strings.Join(keep, string(filepath.ListSeparator))
}
