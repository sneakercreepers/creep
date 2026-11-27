package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
