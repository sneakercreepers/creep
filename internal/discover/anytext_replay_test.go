package discover

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// anyTextFixture records one discovery batch of the flaskpg app's build
// and dependency files, which #366 reads and no other replay sends.
// SYNTHESIZED: the model cites only the canary. Regenerate:
// go test ./internal/discover -run TestAnyTextReplay -update
const anyTextFixture = "testdata/replay/anytext/flaskpg"

// Acceptance (#366 tester): files no inventory row names as source (a
// Dockerfile, a compose file, a requirements list) replay through
// Discoverer.Run in one batch to a complete Result with each file read in
// full, and a wheel (a zip no format row names) is listed binary.
func TestAnyTextReplay(t *testing.T) {
	app := loadApp(t, "flaskpg")
	store, mode := fixtureStoreIn(t, anyTextFixture)
	send := storeSend(store, mode, func(prompt string) ([]byte, error) {
		if !*update {
			return nil, errors.New("replay must not call the model")
		}
		return answering(func(secs []promptSection) any { return honest(secs) })(parseSections(prompt))
	})
	files := os.DirFS(filepath.Join(appsDir, app.name, variantVulnerable))
	d := Discoverer{
		Redactor: newRedactor(t), Model: replayClient(t, send), Tier: replayTier, Seed: testSeed,
		Read: func(p string) ([]byte, error) { return fs.ReadFile(files, p) },
	}
	wheel := "wheels/flask-3.1.2-py3-none-any.whl"
	paths := []string{app.file, "Dockerfile", "compose.yaml", "requirements.txt", wheel}
	res, err := d.Run(context.Background(), paths)
	if err != nil || !res.Complete() {
		t.Fatalf("replay: %v, files %+v; want complete", err, res.Files)
	}
	for i, p := range paths {
		want, reason := CoverageReadFull, ReasonNone
		if p == wheel {
			want, reason = CoverageNotSource, ReasonBinary
		}
		if f := fileOf(t, res, i); f.Coverage != want || f.Reason != reason {
			t.Errorf("%s: %+v, want coverage %d reason %q", p, f, want, reason)
		}
	}
	if n := len(cacheFiles(t, anyTextFixture)); n != 1 {
		t.Fatalf("%d fixture files, want one batch; rerun with -update", n)
	}
}
