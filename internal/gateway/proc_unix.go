//go:build unix

package gateway

import (
	"os/exec"
	"syscall"
)

// runGroup runs the model CLI as the leader of a new process group, makes
// a timeout or the output cap kill that whole group, and after the CLI
// exits kills what is left of the group, so no background child can
// outlive the run or write into the working directory after it is
// checked. An already empty group (ESRCH) is the usual case.
func runGroup(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killGroup(cmd) }
	err := cmd.Run()
	_ = killGroup(cmd)
	return err
}

func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
