// Package planner decides which route→sink hypotheses the reader checks,
// and in which order, from IDs, enums and booleans only.
//
// It exists because the step that decides what to investigate must not be
// steerable by the scanned repository (invariant 3, docs/architecture.md
// §3). Text from the repository can fool the reader; it must never reach
// the planner. The package is built so that it cannot:
//
//   - Input holds route and sink IDs, method bits, sink kinds, auth and
//     argument booleans, the calibration tier and token counts. No type
//     reachable from Input can carry text (no string, byte or rune
//     sequence, map, interface, func, chan or float); text_test.go walks
//     the types by reflection and fails the build's tests if one appears,
//     and checks that Build takes nothing else. The caller copies
//     static.Graph and calibrate.Tier into Input, since planner may import
//     neither static nor reader (the layer table enforces it).
//
//   - Plan, the output, is a closed schema of IDs and enums with no
//     free-text field; the same walk guards it. Every input sink appears
//     exactly once, as a Hypothesis or as Skipped with a closed reason, so
//     the report can list what was not evaluated.
//
//   - Build validates the input and fails closed with ErrInput on unknown
//     enum values, duplicate or dangling IDs, a zero step cost or more than
//     2^20 routes or sinks. Error messages hold only numbers.
//
// Ranking is deterministic and needs no model: the static facts already say
// what matters, and a model call here would add cost and an output to
// trust without adding information. Sinks are ordered by Risk (High: an
// argument that can carry input on a route with no auth seen and no bound
// parameters; Medium: input with auth or bound parameters; Low: a literal
// argument), then unauthenticated first, then unparameterized, then sink
// severity (shell, SQL, NoSQL, template, file, HTTP client), then direct calls
// before helpers, then state-changing methods, then lower sink ID. Only SQL
// sinks have bound parameters: Parameterized on another kind is ignored, so
// a mapping bug cannot demote a shell or file sink.
//
// Each hypothesis is one reader step and reserves Budget.StepTokens, so a
// plan never needs more than Budget.Tokens. The tier bounds the steps:
// S plans at most 32 and skips RiskLow sinks, M at most 256, L at most
// 1024. Sorting is O(n log n) in the sink count; BenchmarkBuild measures
// it.
package planner
