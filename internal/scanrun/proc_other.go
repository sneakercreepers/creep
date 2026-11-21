//go:build !unix && !windows

package scanrun

import "os/exec"

// killTreeOnCancel keeps the default on hosts with neither process groups
// nor taskkill: on timeout only the scanner itself is killed.
func killTreeOnCancel(*exec.Cmd) {}
