package reader

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sneakercreepers/creep/internal/state"
)

var update = flag.Bool("update", false, "rewrite the replay fixtures in testdata/replay from the synthesized model")

const (
	appsDir           = "../../testdata/apps"
	replayDir         = "testdata/replay"
	variantVulnerable = "vulnerable"
	variantSafe       = "safe"
	replayTier        = TierM
)

// appHypothesis is one route→sink hypothesis on a testdata app variant.
// Its fixture must replay to vulnerable on the vulnerable variant and to
// not_vulnerable on the safe twin.
type appHypothesis struct {
	variant string
	class   Class
	route   string
	source  int // the handler's def line (the route call in Express)
	sink    int
}

// appCase is one testdata app: its source file and the hypotheses the
// reader evaluates on it. IDs are each hypothesis's index plus one.
type appCase struct {
	app  string
	file string
	hyps []appHypothesis
}

// appCases holds a hypothesis for every expected.json finding whose class
// the reader has, and the same route on the safe twin.
// TestAppCasesMatchExpected keeps it in step with testdata/apps.
var appCases = []appCase{
	{"express", "app.js", []appHypothesis{
		{variantVulnerable, ClassCommandInjection, "/diagnostics/ping", 50, 52},
		{variantSafe, ClassCommandInjection, "/diagnostics/ping", 64, 69},
	}},
	{"fastapi", "app.py", []appHypothesis{
		{variantVulnerable, ClassSQLInjection, "/items", 43, 44},
		{variantVulnerable, ClassSSRF, "/webhooks/test", 63, 64},
		{variantSafe, ClassSQLInjection, "/items", 46, 50},
		{variantSafe, ClassSSRF, "/webhooks/test", 69, 76},
	}},
	{"flask", "app.py", []appHypothesis{
		{variantVulnerable, ClassSQLInjection, "/notes/search", 40, 44},
		{variantVulnerable, ClassSSRF, "/notes/preview", 58, 61},
		{variantVulnerable, ClassPathTraversal, "/attachments/<path:name>", 66, 68},
		{variantSafe, ClassSQLInjection, "/notes/search", 41, 45},
		{variantSafe, ClassSSRF, "/notes/preview", 61, 70},
		{variantSafe, ClassPathTraversal, "/attachments/<path:name>", 75, 77},
	}},
}

// Acceptance (#95): every testdata app replays through Slicer.Build and
// Evaluate from its committed fixture, with no network, no key and no
// model call, to the verdicts its expected.json implies. Regenerate the
// fixtures with: go test ./internal/reader -run TestAppsReplay -update
func TestAppsReplay(t *testing.T) {
	for _, c := range appCases {
		t.Run(c.app, func(t *testing.T) {
			store, mode := fixtureStore(t, c.app)
			calls := 0
			for _, variant := range []string{variantVulnerable, variantSafe} {
				got, err := runVariant(store, mode, replayTier, c, variant, countingModel(&calls))
				if err != nil {
					t.Fatalf("%s: %v", variant, err)
				}
				for _, err := range c.mismatches(variant, got) {
					t.Errorf("%s: %v", variant, err)
				}
			}
			if !*update && calls != 0 {
				t.Fatalf("replay made %d model calls", calls)
			}
			if n := len(cacheFiles(t, filepath.Join(replayDir, c.app))); n != len(c.hyps) {
				t.Fatalf("%d fixture files for %d hypotheses; rerun with -update", n, len(c.hyps))
			}
		})
	}
}

// fixtureStore opens the app's fixture store. With -update it records into
// testdata/replay/<app>, dropping old recordings first; otherwise it
// replays a copy, so the test never writes into the repository.
func fixtureStore(t *testing.T, app string) (*state.Store, state.Mode) {
	t.Helper()
	dir := filepath.Join(replayDir, app)
	mode := state.ModeReplay
	if *update {
		if err := os.RemoveAll(filepath.Join(dir, "cache")); err != nil {
			t.Fatal(err)
		}
		mode = state.ModeRecord
	} else {
		dir = copyFixtures(t, dir)
	}
	store, err := state.Open(dir, fixtureSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, mode
}

// countingModel is the model behind the fixtures: with -update it answers
// as expected.json implies (synthesizedReply). Replay must never reach it,
// so it fails there; calls counts every attempt.
func countingModel(calls *int) model {
	return func(h appHypothesis) ([]byte, error) {
		*calls++
		if !*update {
			return nil, errors.New("replay must not call the model")
		}
		return synthesizedReply(h)
	}
}

// The safe twin of each vulnerable hypothesis must be evaluated too, and
// both variants' routes must sit at their source lines, so a moved line in
// an app fails here rather than as a confusing replay mismatch.
func TestAppCasesMatchExpected(t *testing.T) {
	dirs, err := os.ReadDir(appsDir)
	if err != nil {
		t.Fatal(err)
	}
	var apps []string
	for _, d := range dirs {
		if d.IsDir() {
			apps = append(apps, d.Name())
		}
	}
	var cased []string
	for _, c := range appCases {
		cased = append(cased, c.app)
		for _, err := range c.checkAgainstApp() {
			t.Errorf("%s: %v", c.app, err)
		}
	}
	if !slices.Equal(apps, cased) {
		t.Fatalf("testdata/apps has %v, appCases has %v: every app needs a case and fixtures", apps, cased)
	}
}
