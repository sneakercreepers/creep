package gateway

import (
	"os/exec"
	"testing"
)

// linkStoreDir makes link a junction to target: Windows makes one without
// privilege, unlike a symbolic link, so the read-path check is tested here.
func linkStoreDir(t *testing.T, target, link string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
}
