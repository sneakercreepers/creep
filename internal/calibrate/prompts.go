package calibrate

import (
	_ "embed" // the system prompts are versioned data in prompts/
	"regexp"
	"strings"
)

// The system prompts, one per call kind. Calibration runs before a tier is
// known, so each has a single variant; PromptVersion names them.
var (
	//go:embed prompts/task.txt
	taskSystem string
	//go:embed prompts/tools.txt
	toolsSystem string
	//go:embed prompts/context.txt
	contextSystem string
)

// promptBudget is the most tokens one call of each kind may take: system
// prompt, output schema and the largest user turn the seeds can produce
// (for context probes, the largest of contextSizes). Raising a budget is a
// reviewed change to this table.
var promptBudget = map[string]int{
	purposeTask:    2600, // the task prompt defines every builtin (ADR 0037)
	purposeTool:    800,
	purposeContext: 132 << 10, // the 128 KiB probe plus 4 KiB for prompt and schema
	// creep doctor's probe: MaxContextFitsBytes plus 4 KiB (#362).
	purposeDoctorContext: MaxContextFitsBytes + 4<<10,
}

// builtinsHeader opens the task prompt's list of builtins; a blank line
// ends it.
const builtinsHeader = "The only builtins:\n"

var (
	builtinCallRe  = regexp.MustCompile(`\b([a-z_][a-z0-9_]*(?:\.[a-z_]+)?)\(`)
	builtinFieldRe = regexp.MustCompile(`(?:^|\s)\.([a-z_]+)\b`)
)

// builtins returns the calls and fields the task prompt defines. The prompt
// is the one list of what the pseudocode may use (ADR 0037): templates call
// nothing else, and no slot value may shadow one.
func builtins() (calls, fields map[string]bool) {
	_, section, _ := strings.Cut(taskSystem, builtinsHeader)
	section, _, _ = strings.Cut(section, "\n\n")
	calls, fields = map[string]bool{}, map[string]bool{}
	for _, m := range builtinCallRe.FindAllStringSubmatch(section, -1) {
		calls[m[1]] = true
	}
	for _, m := range builtinFieldRe.FindAllStringSubmatch(section, -1) {
		fields[m[1]] = true
	}
	return calls, fields
}
