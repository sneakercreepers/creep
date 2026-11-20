//go:build !windows

package cli

import (
	"os"
	"testing"
)

// linkDir makes link a symbolic link to the directory target: the
// directory link a Unix checkout or install leaves.
func linkDir(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s: %v", link, err)
	}
}
