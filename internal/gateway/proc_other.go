//go:build !unix && !windows

package gateway

import "os/exec"

// ownProcessGroup keeps the default on hosts with neither process groups
// nor taskkill: a timeout kills the CLI itself.
func ownProcessGroup(*exec.Cmd) {}

// killTree has nothing to kill on these hosts; see ownProcessGroup.
func killTree(*exec.Cmd) {}
