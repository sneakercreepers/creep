package report

// CalibrationScope is what the calibration behind a report measured
// (#358, ADR 0037): one language-neutral pseudocode task set, so the tier
// and each class's detected / tasks count measure following data from an
// input to a sink, never knowledge of the scanned repository's languages.
// JSON v1 writes it as coverage.calibration_scope (additive); the text
// summary, Markdown and SARIF print CalibrationScopeNote.
const CalibrationScope = "language_neutral"

// CalibrationScopeNote is the sentence every human-readable format prints
// beside the calibration, so a tier never reads as a language rating.
const CalibrationScopeNote = "calibration measures following data from an input to a sink on language-neutral pseudocode tasks, not knowledge of the repository's languages"
