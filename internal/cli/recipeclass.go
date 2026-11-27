package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/recipe"
)

// splitClassWarning names the class a command_injection recipe's sink
// belongs to since ADR 0034, or "" when it is a shell sink. Since #369
// findings at an eval or deserialization sink carry code_injection or
// insecure_deserialization, so such a recipe's hint never reaches them.
// The sink's kind comes from the tripwire table on the vulnerable
// fixture's sink line, so lint holds no language rule of its own. A line
// that also holds a shell sink stays command_injection. r is a parsed
// recipe, so its sink line exists.
func splitClassWarning(r *recipe.Recipe) (string, error) {
	if r.Class != kindClass(discover.SinkShell) {
		return "", nil
	}
	f := r.Fixtures.Vulnerable
	lines := strings.Split(f.Code, "\n")
	kinds, err := discover.SinkKindsOn(lines[f.SinkLine-1])
	if err != nil || slices.Contains(kinds, discover.SinkShell) {
		return "", err
	}
	var split []string
	for _, k := range kinds {
		if k == discover.SinkCodeEval || k == discover.SinkDeserialize {
			split = append(split, kindClass(k))
		}
	}
	if len(split) == 0 {
		return "", nil
	}
	name := strings.Join(split, " or ")
	return fmt.Sprintf("the vulnerable fixture's sink is a %s sink, not a shell: since ADR 0034 its findings are %s, so a command_injection hint never reaches them; set class to %s", name, name, name), nil
}
