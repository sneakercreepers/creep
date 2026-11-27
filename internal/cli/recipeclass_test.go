package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/recipe"
)

// committedRecipe reads one of internal/recipe's committed test recipes.
func committedRecipe(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "recipe", "testdata", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestRecipeLintWarnsOnSplitClass is #371's lint check: a command_injection
// recipe whose vulnerable fixture's sink the tripwire table reads as an
// eval or deserialization sink still passes lint (exit 0), with a warning
// that names the class its findings now carry and quotes no recipe text.
// A shell sink, a line that also holds one, and every other class get no
// warning.
func TestRecipeLintWarnsOnSplitClass(t *testing.T) {
	evalAsCommand := committedRecipe(t, "v1/python-eval-as-command.json")
	pickle := committedRecipe(t, "python-pickle-body.json")
	tests := []struct {
		name, data, warn string // warn "": no warning
	}{
		{"eval as command_injection", evalAsCommand, "set class to code_injection"},
		{"pickle as command_injection", strings.Replace(pickle, `"class": "insecure_deserialization"`, `"class": "command_injection"`, 1), "set class to insecure_deserialization"},
		{"shell sink", committedRecipe(t, "v1/python-shell-ping.json"), ""},
		{"eval inside a shell call", strings.Replace(evalAsCommand, `return str(eval(expr))`, `return str(os.system(eval(expr)))`, 1), ""},
		{"code_injection", committedRecipe(t, "python-eval-request.json"), ""},
		{"insecure_deserialization", pickle, ""},
		{"sql_injection", string(recipe.Template()), ""},
		{"eval only in the safe fixture", strings.Replace(committedRecipe(t, "v1/python-shell-ping.json"), `args = [`, `eval(host); args = [`, 1), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanRepo(t, map[string]string{"r.json": tt.data}, "")
			code, out, stderr := run("recipe", "lint", "r.json")
			if code != exitcode.OK || !strings.Contains(out, ": valid (") {
				t.Fatalf("exit %d: %s%s", code, out, stderr)
			}
			if tt.warn == "" && stderr != "" {
				t.Errorf("unexpected warning: %s", stderr)
			}
			if tt.warn != "" && (!strings.Contains(stderr, "warning: ") || !strings.Contains(stderr, tt.warn)) {
				t.Errorf("no warning naming the class: %q", stderr)
			}
			if strings.Contains(stderr, "expr") || strings.Contains(stderr, "request") {
				t.Errorf("the warning quotes recipe text: %s", stderr)
			}
		})
	}
}

// The new classes have no PoC template whose oracle proves them (ADR
// 0019), so a code_injection or insecure_deserialization recipe with a PoC
// is refused, never loaded with an oracle that proves another class.
func TestSplitClassPoCRefused(t *testing.T) {
	tmpl := string(recipe.Template())
	for _, class := range []string{"code_injection", "insecure_deserialization"} {
		scanRepo(t, map[string]string{"r.json": strings.Replace(tmpl, `"class": "sql_injection"`, `"class": "`+class+`"`, 1)}, "")
		code, _, stderr := run("recipe", "lint", "r.json")
		if code != exitcode.ConfigError || !strings.Contains(stderr, "does not prove "+class) {
			t.Errorf("%s: exit %d: %s", class, code, stderr)
		}
	}
}

// The warning is advisory: when the tripwire table fails to load, lint
// prints no warning and keeps its own verdict and exit code.
func TestSplitClassWarningSkipsBrokenTable(t *testing.T) {
	evalAsCommand := committedRecipe(t, "v1/python-eval-as-command.json")
	saved := sinkKindsOn
	t.Cleanup(func() { sinkKindsOn = saved })
	sinkKindsOn = func(string) ([]discover.SinkKind, error) { return nil, errors.New("tripwire.tsv: broken") }
	tests := []struct {
		name, data string
		code       int
	}{
		{"valid recipe stays valid", evalAsCommand, exitcode.OK},
		{"invalid recipe stays refused", strings.Replace(evalAsCommand, `"version": 1`, `"version": 2`, 1), exitcode.ConfigError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanRepo(t, map[string]string{"r.json": tt.data}, "")
			code, out, stderr := run("recipe", "lint", "r.json")
			if code != tt.code || strings.Contains(stderr, "warning") || strings.Contains(stderr, "tripwire") {
				t.Errorf("exit %d, want %d: %s%s", code, tt.code, out, stderr)
			}
		})
	}
}

// Scan warns once per installed command_injection recipe whose vulnerable
// fixture has only an eval or deserialization sink, and still loads it:
// the warning never changes loading or the exit code. A shell or SQL
// recipe gets none.
func TestScanWarnsOnSplitClassRecipe(t *testing.T) {
	tests := []struct {
		name, data string
		verdict    map[string]string
		warn       bool
	}{
		{"eval as command_injection", committedRecipe(t, "v1/python-eval-as-command.json"), map[string]string{"command_injection@7": "vulnerable"}, true},
		{"shell sink", committedRecipe(t, "v1/python-shell-ping.json"), map[string]string{"command_injection@8": "vulnerable"}, false},
		{"sql_injection", string(recipe.Template()), map[string]string{"sql_injection@9": "vulnerable"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			files := cloneFiles()
			files["recipes/sqli.json"] = tt.data
			if code, out, stderr := run("recipe", "add", pinned, makeClone(t, files)); code != exitcode.OK {
				t.Fatalf("recipe add: exit %d: %s%s", code, out, stderr)
			}
			m := &fakeModel{verdict: tt.verdict}
			code, out, stderr := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--config", cfg)
			if code == exitcode.ConfigError || code == exitcode.ModelOrSandbox {
				t.Fatalf("scan: exit %d: %s%s", code, out, stderr)
			}
			warnings := strings.Count(stderr, "installed recipe sqli.json from "+cloneSource+": warning: ")
			if tt.warn && (warnings != 1 || !strings.Contains(stderr, "set class to code_injection")) {
				t.Errorf("%d warnings, want 1: %s", warnings, stderr)
			}
			if !tt.warn && warnings != 0 {
				t.Errorf("unexpected warning: %s", stderr)
			}
		})
	}
}
