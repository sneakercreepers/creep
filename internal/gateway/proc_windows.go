//go:build windows

package gateway

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// taskkillTimeout bounds the tree kill, so a hung taskkill cannot hold
// the call long past its own timeout.
const taskkillTimeout = 10 * time.Second

// ownProcessGroup makes a timeout or the output cap kill the CLI and every
// process it started. A job object needs golang.org/x/sys or unsafe, both
// barred (invariant 6), so the system's taskkill /T /F walks the tree by
// parent process ID instead (an npm .cmd shim's node.exe is a child of
// cmd.exe). It runs while the CLI is still alive: os/exec holds its
// process handle until Wait returns, so the ID cannot be reused by an
// unrelated process. The CLI is then killed directly as well, in case
// taskkill could not run (#226, ADR 0014, threat model C3).
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		taskkillTree(cmd.Process.Pid)
		return cmd.Process.Kill()
	}
}

// killTree does nothing on Windows: once the CLI has exited its process ID
// is free, and taskkill /T on a reused ID could kill an unrelated tree. A
// helper left behind by a CLI that exited normally can outlive the run
// (residual, threat model C3).
func killTree(*exec.Cmd) {}

// taskkillTree runs %SystemRoot%\System32\taskkill.exe by absolute path,
// with fixed arguments, no shell and an empty environment (os/exec adds
// SYSTEMROOT). Its result is ignored: Kill follows either way.
func taskkillTree(pid int) {
	bin, ok := taskkillPath()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), taskkillTimeout)
	defer cancel()
	// G204: a fixed system program and a numeric process ID.
	kill := exec.CommandContext(ctx, bin, "/T", "/F", "/PID", strconv.Itoa(pid)) //nolint:gosec // G204, see above
	kill.Env = []string{}
	_ = kill.Run()
}

// taskkillPath is taskkill.exe under the Windows directory the operator's
// environment names; a relative or missing SystemRoot runs nothing.
func taskkillPath() (string, bool) {
	root := os.Getenv("SystemRoot")
	if root == "" || !filepath.IsAbs(root) {
		return "", false
	}
	return filepath.Join(root, "System32", "taskkill.exe"), true
}
