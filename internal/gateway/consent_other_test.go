//go:build !unix || aix || solaris

package gateway

import "testing"

func mkfifo(t *testing.T, _ string) {
	t.Helper()
	t.Skip("no FIFOs on this platform")
}
