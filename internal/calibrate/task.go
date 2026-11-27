package calibrate

// Class is a vulnerability class creep calibrates and reports on.
type Class string

// The classes calibration covers, the same ones the vulnerable test apps
// exercise (#16).
const (
	ClassSQLi               Class = "sqli"
	ClassNoSQLInjection     Class = "nosql_injection"
	ClassCommandInjection   Class = "command_injection"
	ClassPathTraversal      Class = "path_traversal"
	ClassSSRF               Class = "ssrf"
	ClassIDOR               Class = "idor"
	ClassMissingAuth        Class = "missing_auth"
	ClassPrototypePollution Class = "prototype_pollution"
)

// Classes returns every calibrated class, in a fixed order.
func Classes() []Class {
	return []Class{
		ClassSQLi, ClassNoSQLInjection, ClassCommandInjection, ClassPathTraversal,
		ClassSSRF, ClassIDOR, ClassMissingAuth, ClassPrototypePollution,
	}
}

// PlannedClasses are the calibrated classes a scan can plan: the ones a
// discover sink kind maps to (internal/cli kindClass, whose test keeps the
// two lists equal). Only these decide the tier and the fitness floor
// (#363): idor, missing_auth and prototype_pollution are still measured
// and reported, but no finding of theirs is ever planned, so a weak score
// there must not hold a model back and a strong one must not lift it.
// Planned classes calibration has no tasks for (template_injection,
// code_injection, insecure_deserialization) cannot be measured, so they
// stay out until the task set covers them (#358).
func PlannedClasses() []Class {
	return []Class{ClassSQLi, ClassNoSQLInjection, ClassCommandInjection, ClassPathTraversal, ClassSSRF}
}

// Language is the source language of a task.
type Language string

// Languages v0.1 supports (docs/architecture.md §7).
const (
	LanguagePython     Language = "python"
	LanguageJavaScript Language = "javascript"
)

// Task is one calibration task: a source file and its ground truth. Only
// Code is meant for the model; the other fields score its answer.
type Task struct {
	ID         string   `json:"id"`         // task-000 to task-099, by position
	Template   string   `json:"template"`   // template directory name
	Class      Class    `json:"class"`      // class the template exercises
	Language   Language `json:"language"`   // source language of Code
	Vulnerable bool     `json:"vulnerable"` // false for the safe twin
	Line       int      `json:"line"`       // 1-based line of the sink, or of its fixed form
	Code       string   `json:"code"`       // file contents, LF line endings
}
