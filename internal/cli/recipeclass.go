package cli

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/recipe"
)

// sinkKindsOn reads a line with the tripwire table; tests replace it to
// make the table fail.
var sinkKindsOn = discover.SinkKindsOn

// splitClassWarning names the class a command_injection recipe's sink
// belongs to since ADR 0034, or "" when it is a shell sink. Since #369
// findings at an eval or deserialization sink carry code_injection or
// insecure_deserialization, so such a recipe's hint never reaches them.
// The sink's kind comes from the tripwire table on the vulnerable
// fixture's sink line, so creep holds no language rule of its own. A line
// that also holds a shell sink stays command_injection. The warning is
// advisory: a table that fails to load gives none, never an error. r is a
// parsed recipe, so its sink line exists.
func splitClassWarning(r *recipe.Recipe) string {
	if r.Class != kindClass(discover.SinkShell) {
		return ""
	}
	f := r.Fixtures.Vulnerable
	lines := strings.Split(f.Code, "\n")
	kinds, err := sinkKindsOn(lines[f.SinkLine-1])
	if err != nil || slices.Contains(kinds, discover.SinkShell) {
		return ""
	}
	var split []string
	for _, k := range kinds {
		if k == discover.SinkCodeEval || k == discover.SinkDeserialize {
			split = append(split, kindClass(k))
		}
	}
	if len(split) == 0 {
		return ""
	}
	name := strings.Join(split, " or ")
	return fmt.Sprintf("class command_injection, but the vulnerable fixture's sink is not a shell sink: since ADR 0034 its findings are %s, so this hint never reaches them; set class to %s", name, name)
}

// warnSplitClass prints r's split-class warning, if any, under label.
func warnSplitClass(w io.Writer, label string, r *recipe.Recipe) {
	if warning := splitClassWarning(r); warning != "" {
		fmt.Fprintf(w, "%s: warning: %s\n", label, warning)
	}
}
