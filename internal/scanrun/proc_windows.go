//go:build windows

package scanrun

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// taskkillTimeout bounds the tree kill, so a hung taskkill cannot hold
// the scan past its own timeout for long.
const taskkillTimeout = 10 * time.Second

// killTreeOnCancel makes a timeout kill the scanner and every process it
// started. A job object needs golang.org/x/sys or unsafe, both barred
// (invariant 6), so the system's taskkill /T /F walks the tree by parent
// process ID instead. It runs while the scanner is still alive: os/exec
// holds its process handle until Wait returns, so the ID cannot be reused
// by an unrelated process. The scanner is then killed directly as well,
// in case taskkill could not run (#226, ADR 0013).
func killTreeOnCancel(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		taskkillTree(cmd.Process.Pid)
		return cmd.Process.Kill()
	}
}

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
