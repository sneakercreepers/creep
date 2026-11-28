package calibrate

// Class is a vulnerability class creep calibrates and reports on.
type Class string

// The classes calibration covers: one per discover sink kind, the classes
// a scan can plan and read (#358).
const (
	ClassSQLi              Class = "sqli"
	ClassNoSQLInjection    Class = "nosql_injection"
	ClassCommandInjection  Class = "command_injection"
	ClassPathTraversal     Class = "path_traversal"
	ClassSSRF              Class = "ssrf"
	ClassTemplateInjection Class = "template_injection"
	ClassCodeInjection     Class = "code_injection"
	ClassDeserialization   Class = "insecure_deserialization"
)

// Classes returns every calibrated class, in a fixed order.
func Classes() []Class {
	return []Class{
		ClassSQLi, ClassNoSQLInjection, ClassCommandInjection, ClassPathTraversal,
		ClassSSRF, ClassTemplateInjection, ClassCodeInjection, ClassDeserialization,
	}
}

// PlannedClasses are the calibrated classes a scan can plan: the ones a
// discover sink kind maps to (internal/cli kindClass, whose test keeps the
// two lists equal). Only these decide the tier and the fitness floor
// (#363). Since the neutral task set (#358) calibration measures exactly
// the planned classes, so this is Classes; it stays a separate name
// because the tier and the floor are defined over what a scan plans.
func PlannedClasses() []Class {
	return Classes()
}

// Task is one calibration task: a pseudocode program and its ground truth.
// Only Code is meant for the model; the other fields score its answer. A
// task names no source language: the tier measures following data from an
// input to a sink, not knowledge of any language (#358).
type Task struct {
	ID         string `json:"id"`         // task-000 to task-063, by position
	Template   string `json:"template"`   // template directory name
	Class      Class  `json:"class"`      // class the template exercises
	Vulnerable bool   `json:"vulnerable"` // false for the safe twin
	Line       int    `json:"line"`       // 1-based line of the sink, or of its fixed form
	Code       string `json:"code"`       // program text, LF line endings
}
