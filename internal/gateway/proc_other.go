//go:build !unix

package gateway

import "os/exec"

// ownProcessGroup keeps the default on Windows: a timeout kills the CLI
// itself. Killing its children needs a job object, which needs
// golang.org/x/sys or unsafe, both barred, so a helper the CLI started can
// outlive the run (ADR 0014, residual risk; threat model C3).
func ownProcessGroup(*exec.Cmd) {}

// killTree has nothing to kill on Windows; see ownProcessGroup.
func killTree(*exec.Cmd) {}
