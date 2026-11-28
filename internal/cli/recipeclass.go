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

// splitKinds are the sink kinds ADR 0034 gave one class each where there
// was one, command_injection.
var splitKinds = []discover.SinkKind{discover.SinkShell, discover.SinkCodeEval, discover.SinkDeserialize}

// splitClassWarning names the class a recipe's sink belongs to when the
// recipe is one of the three split classes (command_injection,
// code_injection, insecure_deserialization) and its sink reads as another
// of them, or "". Findings carry the class of their sink's kind, so such a
// recipe's hint never reaches them. The kind comes from the tripwire table
// on the vulnerable fixture's sink line, so creep holds no language rule
// of its own; a line whose kinds include the recipe's class gets no
// warning. The warning is advisory: a table that fails to load gives
// none, never an error. r is a parsed recipe, so its sink line exists.
func splitClassWarning(r *recipe.Recipe) string {
	if !slices.ContainsFunc(splitKinds, func(k discover.SinkKind) bool { return kindClass(k) == r.Class }) {
		return ""
	}
	f := r.Fixtures.Vulnerable
	lines := strings.Split(f.Code, "\n")
	kinds, err := sinkKindsOn(lines[f.SinkLine-1])
	if err != nil {
		return ""
	}
	var found []string
	for _, k := range kinds {
		if slices.Contains(splitKinds, k) {
			found = append(found, kindClass(k))
		}
	}
	if len(found) == 0 || slices.Contains(found, r.Class) {
		return ""
	}
	name := strings.Join(found, " or ")
	return fmt.Sprintf("class %s, but the tripwire table reads the vulnerable fixture's sink as %s: since ADR 0034 findings there carry that class, so this hint never reaches them; set class to %s", r.Class, name, name)
}

// warnSplitClass prints r's split-class warning, if any, under label.
func warnSplitClass(w io.Writer, label string, r *recipe.Recipe) {
	if warning := splitClassWarning(r); warning != "" {
		fmt.Fprintf(w, "%s: warning: %s\n", label, warning)
	}
}
