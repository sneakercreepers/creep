package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/recipe"
)

// hintBlock opens the reader's HINT block in a request (ADR 0025).
const hintBlock = "HINT (recipe text"

// payloadDeps is fakeDeps that also keeps every request body m gets.
func payloadDeps(m *fakeModel, payloads *[][]byte) scanDeps {
	deps := fakeDeps(m, calibrate.TierM)
	deps.connect = func(*config.Resolved, string, io.Writer) (modelLink, error) {
		send := func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
			*payloads = append(*payloads, bytes.Clone(c.Payload))
			return m.send(ctx, c)
		}
		return modelLink{send: send, close: func() error { return nil }}, nil
	}
	return deps
}

// countHinted counts the requests with a HINT block that also hold want.
func countHinted(payloads [][]byte, want string) int {
	n := 0
	for _, p := range payloads {
		if bytes.Contains(p, []byte(hintBlock)) && bytes.Contains(p, []byte(want)) {
			n++
		}
	}
	return n
}

// Scan loads an installed recipe only after creep.lock verified it and its
// fixtures passed, then gives its hint to the reader for the files it
// covers.
func TestScanLoadsVerifiedRecipes(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	installTemplate(t)
	var payloads [][]byte
	m := rightRecipeModel()
	code, out, stderr := runScanWith(payloadDeps(m, &payloads), "scan", "--config", cfg)
	if code == exitcode.ConfigError || code == exitcode.ModelOrSandbox {
		t.Fatalf("scan: exit %d: %s%s", code, out, stderr)
	}
	assertContains(t, "stderr", stderr, []string{"recipes: checking the fixtures of 1 installed recipe files"})
	// The first two calls are the fixture checks; at least one reader call
	// of the scan's own must carry the hint too.
	if len(payloads) < 3 || countHinted(payloads[:2], "") != 2 {
		t.Fatalf("the fixture checks were not the first, hinted calls (%d calls)", len(payloads))
	}
	if countHinted(payloads[2:], "") == 0 {
		t.Error("no reader call of the scan got the installed recipe's hint")
	}
}

// A recipe whose fixtures the model gets wrong at the scan's tier fails
// the scan with exit 2; a model failure on them exits 3. Neither runs
// discovery.
func TestScanRefusesFailingInstalledRecipe(t *testing.T) {
	tests := []struct {
		name  string
		model *fakeModel
		code  int
		want  string
	}{
		{"safe fixture flagged", &fakeModel{verdict: map[string]string{"sql_injection": "vulnerable"}}, exitcode.ConfigError, "the safe fixture was not clean"},
		{"model down", &fakeModel{fail: map[string]error{"sql_injection": io.ErrUnexpectedEOF}}, exitcode.ModelOrSandbox, "unexpected EOF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			installTemplate(t)
			code, _, stderr := runScanWith(fakeDeps(tt.model, calibrate.TierM), "scan", "--config", cfg)
			if code != tt.code || !strings.Contains(stderr, tt.want) || !strings.Contains(stderr, "sqli.json from "+cloneSource) || tt.model.discovered != 0 {
				t.Errorf("exit %d, want %d, %d discovery calls: %s", code, tt.code, tt.model.discovered, stderr)
			}
		})
	}
}

// Acceptance criterion 1 of #34: changing an installed recipe file, or the
// lock, after install fails the next scan closed (exit 2) before any model
// call.
func TestTamperedRecipeFailsScan(t *testing.T) {
	pin := recipe.Pin{Source: cloneSource, Commit: cloneCommit, File: "sqli.json"}
	tests := []struct {
		name   string
		tamper func(t *testing.T)
		want   string
	}{
		{"one byte changed", func(t *testing.T) {
			editFile(t, storeFile(t, pin.Path()), func(s string) string { return strings.Replace(s, "execute(", "execuse(", 1) })
		}, "does not match creep.lock"},
		{"newline appended", func(t *testing.T) {
			editFile(t, storeFile(t, pin.Path()), func(s string) string { return s + "\n" })
		}, "does not match creep.lock"},
		{"file removed", func(t *testing.T) {
			if err := os.Remove(storeFile(t, pin.Path())); err != nil {
				t.Fatal(err)
			}
		}, "is missing"},
		{"lock checksum edited", func(t *testing.T) {
			editFile(t, storeFile(t, recipe.LockFile), func(s string) string { return strings.Replace(s, "sha256:", "sha256:0", 1) })
		}, "creep.lock refused"},
		{"lock pinned to a branch", func(t *testing.T) {
			editFile(t, storeFile(t, recipe.LockFile), func(s string) string { return strings.ReplaceAll(s, cloneCommit, "main") })
		}, "creep.lock refused"},
		{"lock points outside the store", func(t *testing.T) {
			editFile(t, storeFile(t, recipe.LockFile), func(s string) string { return strings.Replace(s, `"sqli.json"`, `"../../../../x.json"`, 1) })
		}, "creep.lock refused"},
		{"file swapped for a valid other recipe", func(t *testing.T) {
			editFile(t, storeFile(t, pin.Path()), func(s string) string {
				return strings.Replace(s, "python-sql-string-concat", "python-sql-other", 1)
			})
		}, "does not match creep.lock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			installTemplate(t)
			tt.tamper(t)
			m := rightRecipeModel()
			code, _, stderr := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--config", cfg)
			if code != exitcode.ConfigError || !strings.Contains(stderr, tt.want) || m.calls != 0 {
				t.Errorf("exit %d, %d model calls, want 2, none and %q: %s", code, m.calls, tt.want, stderr)
			}
		})
	}
}

// Acceptance criterion 2 of #34: the policy's recipe_sources is enforced
// on install and on every scan, and a bad entry is a config error.
func TestRecipePolicyAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		allowed bool
	}{
		{"no allowlist", "consent: []\n", true},
		{"exact source", "recipe_sources: [github.com/acme/recipes]\n", true},
		{"owner wildcard", "recipe_sources: [\"github.com/acme/*\"]\n", true},
		{"other source", "recipe_sources: [github.com/other/recipes]\n", false},
		{"empty allowlist", "recipe_sources: []\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			if code, _, stderr := run("recipe", "add", pinned, makeClone(t, cloneFiles())); code != exitcode.OK {
				t.Fatalf("add with no policy: exit %d: %s", code, stderr)
			}
			t.Setenv(policyEnv, writeOutside(t, "policy.yaml", tt.policy))
			code, _, stderr := run("recipe", "add", pinned, makeClone(t, cloneFiles()))
			if tt.allowed != (code == exitcode.OK) || (!tt.allowed && !strings.Contains(stderr, "recipe_sources allowlist")) {
				t.Errorf("add: exit %d: %s", code, stderr)
			}
			m := rightRecipeModel()
			code, _, stderr = runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--config", cfg)
			if !tt.allowed && (code != exitcode.ConfigError || m.calls != 0 || !strings.Contains(stderr, "recipe_sources allowlist")) {
				t.Errorf("scan of a source the policy dropped: exit %d, %d calls: %s", code, m.calls, stderr)
			}
		})
	}
	scanRepo(t, nil, "")
	for _, bad := range []string{"recipe_sources: [\"*\"]\n", "recipe_sources: [github.com/acme/recipes@" + cloneCommit + "]\n", "recipe_sources: github.com/acme/recipes\n"} {
		t.Setenv(policyEnv, writeOutside(t, "policy.yaml", bad))
		if code, _, stderr := run("config", "explain"); code != exitcode.ConfigError || !strings.Contains(stderr, "CREEP_POLICY") && !strings.Contains(stderr, "policy") {
			t.Errorf("policy %q: exit %d: %s", bad, code, stderr)
		}
	}
}

// The project file can never add a recipe source or lift the allowlist:
// recipe_sources is not a config key, so creep.yaml or --config naming it
// fails to load, and a creep.lock or recipes/ in the scanned repository is
// never read.
func TestProjectFileCannotAddRecipeSources(t *testing.T) {
	key := "recipe_sources: [\"github.com/acme/*\"]\n"
	scanRepo(t, map[string]string{"creep.yaml": key}, "")
	if code, _, stderr := run("config", "explain"); code != exitcode.ConfigError || !strings.Contains(stderr, `unknown key "recipe_sources"`) {
		t.Errorf("creep.yaml recipe_sources: exit %d: %s", code, stderr)
	}
	t.Setenv(policyEnv, writeOutside(t, "policy.yaml", "recipe_sources: []\n"))
	if code, _, stderr := run("recipe", "add", pinned, makeClone(t, cloneFiles())); code != exitcode.ConfigError {
		t.Errorf("creep.yaml lifted an empty policy allowlist: exit %d: %s", code, stderr)
	}
	explicit := writeOutside(t, "explicit.yaml", key)
	if code, _, stderr := run("config", "explain", "--config", explicit); code != exitcode.ConfigError || !strings.Contains(stderr, "recipe_sources") {
		t.Errorf("--config recipe_sources: exit %d: %s", code, stderr)
	}
}

// A creep.lock, a recipes/ directory or a .creep/recipes store in the
// scanned repository is never read: scan loads only the operator's store.
func TestScanIgnoresRepositoryRecipes(t *testing.T) {
	planted := map[string]string{
		"app.py":                    "@flask",
		"creep.lock":                lockFor(t),
		"recipes/sqli.json":         string(recipe.Template()),
		".creep/recipes/creep.lock": lockFor(t),
		".creep/recipes/acme/recipes/" + cloneCommit + "/sqli.json": string(recipe.Template()),
	}
	cfg := scanRepo(t, planted, "")
	var payloads [][]byte
	code, out, stderr := runScanWith(payloadDeps(rightRecipeModel(), &payloads), "scan", "--config", cfg)
	if code == exitcode.ConfigError || strings.Contains(stderr, "recipes: checking") || countHinted(payloads, "") != 0 {
		t.Errorf("a scan read recipes planted in the repository: exit %d: %s%s", code, out, stderr)
	}
}

// lockFor is a valid lock for the template recipe from cloneSource.
func lockFor(t *testing.T) string {
	t.Helper()
	src, err := recipe.ParseSource(pinned)
	if err != nil {
		t.Fatal(err)
	}
	data, err := recipe.NewLock().Install(src, map[string][]byte{"sqli.json": recipe.Template()}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// editFile rewrites path through edit.
func editFile(t *testing.T, path string, edit func(string) string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, edit(string(data)))
}
