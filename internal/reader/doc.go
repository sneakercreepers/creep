// Package reader asks the model whether one hypothesis holds in a slice of
// redacted code, and turns the answer into a verdict the planner can use.
//
// It exists because the reader is the only step that shows repository text
// to a model, so it is the step a prompt injection in that text can fool.
// The package is built so that a fooled reader has nowhere to write
// instructions (docs/architecture.md §3: planner and reader never import
// each other):
//
//   - Prompts are versioned data (prompts.go): one system prompt per tier,
//     embedded from prompts/{s,m,l}.txt and named by PromptVersion. Each has
//     a token budget that covers the prompt and the output schema sent with
//     it; prompts_test.go fails when a prompt grows past it. Tokens are
//     counted as bytes, the same upper bound models reserves per call.
//   - The model's reply decodes into Answer, a closed struct (output.go):
//     models.Complete refuses unknown fields, prose around the JSON object
//     and wrong types, then Answer.Validate allows only a verdict from the
//     enum, at most MaxEvidence ascending, non-overlapping line ranges and
//     an integer confidence from 0 to 100. Schema and Grammar send the same
//     shape to endpoints that can constrain output.
//   - Project (signal.go) checks the ranges against the lines the model was
//     shown and returns a Signal: hypothesis ID, verdict enum, confidence
//     and line numbers. Signal is the only reader output the planner may
//     receive, and signal_test.go fails if a string, byte slice, map,
//     interface or any other type that can carry text becomes reachable
//     from it, so free text from the model can never reach planner input.
//
// Building slices (#94) and calling the model per hypothesis (#13) are not
// here yet; both must send the user turn as gateway.FileScan fragments of
// redact.File output.
package reader
