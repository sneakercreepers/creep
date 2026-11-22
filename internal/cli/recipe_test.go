package cli

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/recipe"
)

// rightRecipeModel flags the template's vulnerable fixture (sink line 9)
// and clears its safe one.
func rightRecipeModel() *fakeModel {
	return &fakeModel{verdict: map[string]string{"sql_injection@9": "vulnerable"}}
}

// The authoring loop: new writes the template once, lint passes it with no
// model call, test loads it through the reader with two model calls.
func TestRecipeNewLintTest(t *testing.T) {
	cfg := scanRepo(t, nil, "")
	m := rightRecipeModel()
	deps := fakeDeps(m, calibrate.TierM)
	if code, out, stderr := runScanWith(deps, "recipe", "new", "r.json"); code != exitcode.OK || !strings.Contains(out, "wrote r.json") {
		t.Fatalf("new: exit %d: %s%s", code, out, stderr)
	}
	if data, err := os.ReadFile("r.json"); err != nil || string(data) != string(recipe.Template()) {
		t.Fatalf("new wrote %q, %v", data, err)
	}
	if code, _, stderr := runScanWith(deps, "recipe", "new", "r.json"); code != exitcode.ConfigError || !strings.Contains(stderr, "exists") {
		t.Errorf("new over an existing file: exit %d: %s", code, stderr)
	}
	if code, out, stderr := runScanWith(deps, "recipe", "lint", "r.json"); code != exitcode.OK || !strings.Contains(out, "valid (sql_injection)") || m.calls != 0 {
		t.Errorf("lint: exit %d, %d model calls: %s%s", code, m.calls, out, stderr)
	}
	code, out, stderr := runScanWith(deps, "recipe", "test", "--config", cfg, "r.json")
	if code != exitcode.OK || !strings.Contains(out, "loaded at tier M") || m.calls != 2 {
		t.Errorf("test: exit %d, %d model calls: %s%s", code, m.calls, out, stderr)
	}
	if !strings.Contains(stderr, "sends the recipe's hint and its two fixtures, redacted, to endpoint https://models.example.invalid/v1") {
		t.Errorf("test does not say where it sends: %s", stderr)
	}
}

// Acceptance criterion 1 of #33 through the CLI: a recipe whose fixtures
// the model gets wrong is refused with exit 2; a model failure exits 3; no
// outcome but a pass exits 0.
func TestRecipeTestRefusesFailingFixtures(t *testing.T) {
	tests := []struct {
		name  string
		model *fakeModel
		code  int
		want  string
	}{
		{"safe fixture flagged", &fakeModel{verdict: map[string]string{"sql_injection": "vulnerable"}}, exitcode.ConfigError, "the safe fixture was not clean"},
		{"vulnerable fixture missed", &fakeModel{}, exitcode.ConfigError, "the vulnerable fixture was not flagged"},
		{"invalid answer", &fakeModel{verdict: map[string]string{"sql_injection": "invalid"}}, exitcode.ModelOrSandbox, "vulnerable fixture"},
		{"model down", &fakeModel{fail: map[string]error{"sql_injection": errors.New("endpoint down")}}, exitcode.ModelOrSandbox, "endpoint down"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"r.json": string(recipe.Template())}, "")
			code, out, stderr := runScanWith(fakeDeps(tt.model, calibrate.TierM), "recipe", "test", "--config", cfg, "r.json")
			if code != tt.code || !strings.Contains(stderr, tt.want) || strings.Contains(out, "loaded") {
				t.Errorf("exit %d, want %d: %s%s", code, tt.code, out, stderr)
			}
		})
	}
	cfg := scanRepo(t, map[string]string{"r.json": string(recipe.Template())}, "")
	if code, _, stderr := runScanWith(fakeDeps(rightRecipeModel(), calibrate.TierM), "recipe", "test", "r.json"); code != exitcode.ConfigError || !strings.Contains(stderr, "model.endpoint") {
		t.Errorf("test with no model config: exit %d: %s", code, stderr)
	}
	m := rightRecipeModel()
	if code, _, _ := runScanWith(fakeDeps(m, calibrate.TierM), "recipe", "test", "--config", cfg, "--replay", "r.json"); code == exitcode.OK || m.calls != 0 {
		t.Errorf("a replay with no recording loaded the recipe (exit %d, %d calls)", code, m.calls)
	}
}

// TestRecipePathsRefused: a recipe path is the operator's, relative to the
// working directory, and checked before anything opens it: no traversal,
// absolute or device path, link, special file or oversized file.
func TestRecipePathsRefused(t *testing.T) {
	scanRepo(t, map[string]string{
		"big.json":   strings.Repeat(" ", recipe.MaxFileBytes+1),
		"dir.json/x": "",
		"ok.json":    string(recipe.Template()),
	}, "")
	outside := filepath.Join(t.TempDir(), "outside.json")
	mustWrite(t, outside, string(recipe.Template()))
	paths := []string{
		"", "/etc/passwd.json", outside, "../ok.json", "a/../ok.json", "./ok.json", "ok.txt",
		`a\ok.json`, "C:ok.json", "ok.json:stream.json", "big.json", "dir.json", "missing.json",
	}
	if err := os.Symlink(outside, "link.json"); err == nil {
		paths = append(paths, "link.json")
	}
	linkDir(t, filepath.Dir(outside), "linked")
	paths = append(paths, "linked/outside.json")
	if runtime.GOOS == "windows" {
		paths = append(paths, "NUL", "CON")
	}
	for _, p := range paths {
		for _, sub := range []string{"lint", "test", "new"} {
			if sub == "new" && p == "missing.json" {
				continue // new writes a missing file; every other path is refused
			}
			code, stderr := runRecipeWithin(t, sub, p)
			if code != exitcode.ConfigError || strings.Contains(stderr, "loaded") {
				t.Errorf("recipe %s %q: exit %d: %s", sub, p, code, stderr)
			}
		}
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != string(recipe.Template()) {
		t.Errorf("a refused new wrote outside the tree: %v", err)
	}
}

// A recipe's PoC is held to the verify rules a model's PoC meets: a closed
// template, its bounded parameters, and an oracle that proves the class.
func TestRecipePoCChecked(t *testing.T) {
	tmpl := string(recipe.Template())
	tests := []struct {
		name, data, want string
	}{
		{"template for another class", strings.Replace(tmpl, `"class": "sql_injection"`, `"class": "path_traversal"`, 1), "does not prove path_traversal"},
		{"class with no template", strings.Replace(tmpl, `"class": "sql_injection"`, `"class": "ssrf"`, 1), "does not prove ssrf"},
		{"unknown template", strings.Replace(tmpl, `"template": "sql_payload"`, `"template": "shell"`, 1), "template must be"},
		{"unbounded parameter", strings.Replace(tmpl, `"technique": "delay"`, `"technique": "drop_table"`, 1), "technique must be"},
		{"host in the path", strings.Replace(tmpl, `"/users?name=__CREEP_PAYLOAD__"`, `"http://evil.example/x"`, 1), "poc"},
		{"unknown parameter", strings.Replace(tmpl, `"context": "string",`, `"context": "string", "host": "evil.example",`, 1), "not a PoC template"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanRepo(t, map[string]string{"r.json": tt.data}, "")
			code, _, stderr := run("recipe", "lint", "r.json")
			if code != exitcode.ConfigError || !strings.Contains(stderr, tt.want) {
				t.Errorf("exit %d: %s", code, stderr)
			}
		})
	}
}

// Recipes never come from the scanned repository (ADR 0025): no config
// layer has a key for them, so creep.yaml can add or loosen none, and a
// file the repository plants under .creep or recipes/ is never read.
func TestProjectFileCannotAddRecipes(t *testing.T) {
	for _, key := range []string{"recipes: [r.json]\n", "recipe:\n  path: r.json\n"} {
		scanRepo(t, map[string]string{"creep.yaml": key, "r.json": string(recipe.Template())}, "")
		if code, _, stderr := run("config", "explain"); code != exitcode.ConfigError || !strings.Contains(stderr, "recipe") {
			t.Errorf("creep.yaml %q: exit %d: %s", key, code, stderr)
		}
	}
}

// Usage errors never exit 0.
func TestRecipeUsage(t *testing.T) {
	scanRepo(t, nil, "")
	for _, args := range [][]string{{"recipe"}, {"recipe", "lint"}, {"recipe", "run", "r.json"}, {"recipe", "lint", "a.json", "b.json"}} {
		if code, _, stderr := run(args...); code != exitcode.ConfigError || stderr == "" {
			t.Errorf("%v: exit %d: %s", args, code, stderr)
		}
	}
}

// runRecipeWithin runs "creep recipe sub p" and fails the test if it hangs,
// as an open of a planted FIFO would.
func runRecipeWithin(t *testing.T, sub, p string) (int, string) {
	t.Helper()
	type result struct {
		code   int
		stderr string
	}
	done := make(chan result, 1)
	go func() {
		code, _, stderr := run("recipe", sub, p)
		done <- result{code, stderr}
	}()
	select {
	case r := <-done:
		return r.code, r.stderr
	case <-time.After(10 * time.Second):
		t.Fatalf("creep recipe %s %q hung", sub, p)
		return 0, ""
	}
}
