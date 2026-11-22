//go:build !windows

package gateway

import "testing"

// linkStoreDir makes link a symbolic link to target.
func linkStoreDir(t *testing.T, target, link string) {
	t.Helper()
	symlink(t, target, link)
}
