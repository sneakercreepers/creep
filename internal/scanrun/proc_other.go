//go:build !unix && !windows

package scanrun

import "os/exec"

// runTree keeps the default on hosts with neither process groups nor
// taskkill: on timeout only the scanner itself is killed.
func runTree(cmd *exec.Cmd) error {
	return cmd.Run()
}
