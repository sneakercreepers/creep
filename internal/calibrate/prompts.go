package calibrate

import _ "embed" // the system prompts are versioned data in prompts/

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
	purposeTask:    2000,
	purposeTool:    800,
	purposeContext: 132 << 10, // the 128 KiB probe plus 4 KiB for prompt and schema
	// creep doctor's probe: MaxContextFitsBytes plus 4 KiB (#362).
	purposeDoctorContext: MaxContextFitsBytes + 4<<10,
}
