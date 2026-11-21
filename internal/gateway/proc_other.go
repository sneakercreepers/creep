//go:build !unix && !windows

package gateway

import "os/exec"

// runGroup keeps the default on hosts with neither process groups nor
// taskkill: a timeout kills the CLI itself.
func runGroup(cmd *exec.Cmd) error {
	return cmd.Run()
}
