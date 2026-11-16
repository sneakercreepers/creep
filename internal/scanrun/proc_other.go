//go:build !unix

package scanrun

import "os/exec"

// killTreeOnCancel keeps the default: on timeout only the scanner itself
// is killed. A Windows job object needs golang.org/x/sys or unsafe, both
// barred, so a helper process the tool started could outlive the run
// (ADR 0013, residual risk; PATH is empty, so a tool can start none by name).
func killTreeOnCancel(*exec.Cmd) {}
