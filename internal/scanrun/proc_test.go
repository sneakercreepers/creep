package scanrun

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/repofile"
)

// TestTimeoutKillsProcessTree: a helper the scanner started dies with it
// on timeout: on Unix the scanner runs in its own process group, and on
// Windows taskkill /T kills the tree while the scanner's ID is pinned
// (#226).
func TestTimeoutKillsProcessTree(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := installFake(t, base, "tree", "gitleaks")
	limits := testLimits()
	limits.Timeout = time.Second
	got := Run(context.Background(), Job{Scanner: repofile.ScannerGitleaks, Bin: bin, Repo: repo, Limits: limits})
	if got.Outcome != Failed || got.Failure != FailTimeout {
		t.Fatalf("Run = %+v, want a timeout", got)
	}
	dir := filepath.Dir(bin)
	if _, err := os.Stat(filepath.Join(dir, "started")); err != nil {
		t.Fatalf("the helper never started: %v", err)
	}
	if helperBeating(t, filepath.Join(dir, "beat")) {
		t.Error("the helper outlived the timed-out scanner")
	}
}

// helperBeating reports whether a helper still rewrites beat. Run returns
// only after the kill, so the check does not depend on how long the kill
// took: the file is removed, a settle lets a write already in flight land,
// it is removed again, and a live helper recreates it within the window.
func helperBeating(t *testing.T, beat string) bool {
	t.Helper()
	for _, wait := range []time.Duration{200 * time.Millisecond, 300 * time.Millisecond} {
		removeBeat(t, beat)
		time.Sleep(wait)
	}
	_, err := os.Stat(beat)
	return err == nil
}

// removeBeat removes beat, retrying while a writer holds it open, which
// Windows refuses to delete.
func removeBeat(t *testing.T, beat string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := os.Remove(beat)
		if err == nil || os.IsNotExist(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("remove %s: %v", beat, err)
		}
		time.Sleep(beatEvery)
	}
}
