//go:build unix

package gateway

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup starts the model CLI as the leader of a new process group,
// and makes a timeout or the output cap kill that whole group, so a helper
// the CLI started cannot outlive the run.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killGroup(cmd) }
}

// killTree kills what is left of the CLI's process group after it exited,
// so no background child can write into the working directory after it is
// checked. An already empty group (ESRCH) is the usual case.
func killTree(cmd *exec.Cmd) {
	_ = killGroup(cmd)
}

func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
