//go:build unix

package scanrun

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/static"
)

// TestTimeoutKillsProcessTree: a helper the scanner started dies with it
// on timeout, because the scanner runs in its own process group.
func TestTimeoutKillsProcessTree(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := installFake(t, base, "tree", "gitleaks")
	limits := testLimits()
	limits.Timeout = time.Second
	got := Run(context.Background(), Job{Scanner: static.ScannerGitleaks, Bin: bin, Repo: repo, Limits: limits})
	if got.Outcome != Failed || got.Failure != FailTimeout {
		t.Fatalf("Run = %+v, want a timeout", got)
	}
	dir := filepath.Dir(bin)
	if _, err := os.Stat(filepath.Join(dir, "started")); err != nil {
		t.Fatalf("the helper never started: %v", err)
	}
	time.Sleep(3 * time.Second) // past the helper's 2 s sleep
	if _, err := os.Stat(filepath.Join(dir, "survived")); err == nil {
		t.Error("the helper outlived the timed-out scanner")
	}
}
