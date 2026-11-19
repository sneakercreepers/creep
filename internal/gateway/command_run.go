package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// waitDelay bounds how long Wait waits for a killed program's children to
// close stdout, so a grandchild holding the pipe cannot hang a run.
const waitDelay = 2 * time.Second

// maxLeftovers caps the names a ToolUseError keeps.
const maxLeftovers = 16

var (
	// ErrCommandTimeout means the program ran past model.timeout and was killed.
	ErrCommandTimeout = errors.New("model command timed out")
	// ErrCommandFailed is wrapped by *CommandExitError.
	ErrCommandFailed = errors.New("model command failed")
	// ErrToolUse is wrapped by *ToolUseError.
	ErrToolUse = errors.New("model command used a tool")
)

// CommandExitError is a program that exited non-zero or could not start.
// Its stderr is never kept: it may echo the prompt.
type CommandExitError struct {
	Code int // -1 when the program did not start or was killed
}

func (e *CommandExitError) Error() string {
	if e.Code < 0 {
		return "model command did not start or was killed"
	}
	return fmt.Sprintf("model command exited with status %d", e.Code)
}

func (e *CommandExitError) Unwrap() error { return ErrCommandFailed }

// ToolUseError means the program left files in its empty working directory:
// the model CLI has tools (file writes, a shell) and acted on the prompt.
// The reply is discarded. Created holds at most 16 entry names, sorted;
// they were chosen by the model, so print them escaped or not at all.
type ToolUseError struct {
	Created []string
}

func (e *ToolUseError) Error() string {
	return fmt.Sprintf("model command created %d entries in its working directory; it has tools enabled and its output is not used", len(e.Created))
}

func (e *ToolUseError) Unwrap() error { return ErrToolUse }

// run executes the program once with payload on stdin, in a fresh empty
// working directory (never the repository, never under the system temp
// directory; see newRunRoot) with its own temp directory, and
// returns stdout. Checks, in order: anything left in the working directory
// (*ToolUseError), stdout over the cap, the timeout, the exit status.
func (c *Command) run(ctx context.Context, payload []byte) ([]byte, error) {
	root, err := newRunRoot()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	work, tmp := filepath.Join(root, "work"), filepath.Join(root, "tmp")
	for _, d := range []string{work, tmp} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return nil, fmt.Errorf("model command: temp dir: %w", err)
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	out := &cappedBuffer{max: c.maxOut, onFull: cancel}
	cmd := c.start(runCtx, work, tmp, payload, out)
	runErr := cmd.Run()
	// The working directory is checked only once the whole process group is
	// gone, so a background child cannot write into it after the check.
	killTree(cmd)
	return c.outcome(ctx, runCtx, work, out, runErr)
}

func (c *Command) start(ctx context.Context, work, tmp string, payload []byte, out *cappedBuffer) *exec.Cmd {
	// G204: path and args come from model.run (operator config only, never the
	// project file), split without a shell; see NewCommand.
	cmd := exec.CommandContext(ctx, c.path, c.args...) //nolint:gosec
	cmd.Dir = work
	cmd.Env = append(slices.Clip(c.env), "TMPDIR="+tmp, "TEMP="+tmp, "TMP="+tmp)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Stdout = out
	cmd.Stderr = nil // the null device: stderr may echo the prompt
	cmd.WaitDelay = waitDelay
	ownProcessGroup(cmd)
	return cmd
}

func (c *Command) outcome(ctx, runCtx context.Context, work string, out *cappedBuffer, runErr error) ([]byte, error) {
	if created := leftovers(work); len(created) > 0 {
		return nil, &ToolUseError{Created: created}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if out.isFull() {
		return nil, ErrResponseTooLarge
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return nil, ErrCommandTimeout
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return nil, &CommandExitError{Code: exitErr.ExitCode()}
	}
	if runErr != nil {
		return nil, &CommandExitError{Code: -1}
	}
	return out.bytes(), nil
}

// leftovers lists the working directory. An unreadable directory counts as
// used: something changed it.
func leftovers(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{"(unreadable working directory)"}
	}
	var names []string
	for _, e := range entries {
		if len(names) == maxLeftovers {
			break
		}
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

// cappedBuffer keeps at most max bytes. Past that it calls onFull, which
// kills the program, and drops the rest so the program never blocks.
type cappedBuffer struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	max    int
	full   bool
	onFull func()
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.full {
		return len(p), nil
	}
	if b.buf.Len()+len(p) > b.max {
		b.full = true
		b.onFull()
		return len(p), nil
	}
	b.buf.Write(p)
	return len(p), nil
}

func (b *cappedBuffer) isFull() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.full
}

func (b *cappedBuffer) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}
