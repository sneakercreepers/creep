//go:build windows

package scanrun

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"
)

// taskkillTimeout bounds the tree kill, so a hung taskkill cannot hold
// the scan past its own timeout for long.
const taskkillTimeout = 10 * time.Second

// runTree runs the scanner so that a timeout kills it and every process it
// started. A job object needs golang.org/x/sys or unsafe, both barred
// (invariant 6), so the system's taskkill /T /F walks the tree by parent
// process ID instead. Windows reuses an ID once every handle on the
// process is closed, and os/exec closes its own as soon as the scanner
// exits, which can be before Cancel runs. So a second handle, opened right
// after the start while the ID is still the scanner's, pins the ID until
// Wait has returned, and taskkill runs only while that pin is held. The
// scanner is then killed directly as well, in case taskkill could not run
// (#226, ADR 0013).
func runTree(cmd *exec.Cmd) error {
	var pin atomic.Pointer[os.Process]
	cmd.Cancel = func() error {
		if p := pin.Load(); p != nil {
			taskkillTree(p.Pid)
		}
		return cmd.Process.Kill()
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if p, err := os.FindProcess(cmd.Process.Pid); err == nil {
		pin.Store(p)
		defer p.Release() //nolint:errcheck // closing a handle; nothing to do on error
	}
	return cmd.Wait() // returns only after Cancel has
}

// taskkillTree runs taskkill.exe from System32 by absolute path, with fixed
// arguments, no shell, an empty environment (os/exec adds SYSTEMROOT) and
// System32 as its working directory, so the scanned repository is not on
// its DLL search path. Its result is ignored: Kill follows either way.
func taskkillTree(pid int) {
	bin, ok := taskkillPath(os.Getenv("SystemRoot"))
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), taskkillTimeout)
	defer cancel()
	// G204: a fixed system program and a numeric process ID.
	kill := exec.CommandContext(ctx, bin, "/T", "/F", "/PID", strconv.Itoa(pid)) //nolint:gosec // G204, see above
	kill.Dir, kill.Env = filepath.Dir(bin), []string{}
	_ = kill.Run()
}

// taskkillPath is taskkill.exe under the Windows directory root, which must
// be an absolute path on a drive letter: a relative, UNC or \\?\ root runs
// nothing, so taskkill never comes from the current directory or a share.
func taskkillPath(root string) (string, bool) {
	vol := filepath.VolumeName(root)
	if len(vol) != 2 || vol[1] != ':' || !filepath.IsAbs(root) {
		return "", false
	}
	return filepath.Join(root, "System32", "taskkill.exe"), true
}
