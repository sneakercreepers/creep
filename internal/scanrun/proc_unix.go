//go:build unix

package scanrun

import (
	"os/exec"
	"syscall"
)

// runTree runs the scanner in its own process group and, on timeout,
// kills the whole group, so a helper the tool started cannot outlive the
// run.
func runTree(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return cmd.Run()
}
