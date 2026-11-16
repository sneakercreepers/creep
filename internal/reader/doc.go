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
//
//   - The model's reply decodes into Answer, a closed struct (output.go):
//     models.Complete refuses unknown, duplicate and case-variant keys, prose around the JSON object
//     and wrong types, then Answer.Validate allows only a verdict from the
//     enum, at most MaxEvidence ascending, non-overlapping line ranges and
//     an integer confidence from 0 to 100. Schema and Grammar send the same
//     shape to endpoints that can constrain output.
//
//   - Project (signal.go) checks the ranges against the lines the model was
//     shown and returns a Signal: hypothesis ID, verdict enum, confidence
//     and line numbers. Signal is the only reader output the planner may
//     receive, and signal_test.go fails if a string, byte slice, map,
//     interface or any other type that can carry text becomes reachable
//     from it, so free text from the model can never reach planner input.
//
//   - Slicer.Build (slice.go) builds the user turn for each route→sink
//     hypothesis from redact.File output only: each file is redacted whole
//     before a line is picked, and the raw content is used only to check
//     that redaction kept every line in place. The slice holds the sink
//     line, the handler's def, decorators and def continuation, the def
//     around the sink, then the assignments and guards that reach the sink
//     (flow.go: a backward walk by names and Python indentation, each walk
//     capped at maxScanBytes). Lines are numbered as in the file and Shown
//     lists them, so Project refuses citations of lines not shown.
//
//   - Each tier caps the user turn (sliceBudget in render.go; prompts_test.go
//     holds system prompt, schema and slice under one budget). A slice over
//     it keeps its most important lines, cuts long lines, ends with a note
//     and is marked Partial; it is never dropped. A file Read or redact.File
//     rejects is listed as not scanned and its hypotheses as not evaluated;
//     redact.ErrRunFull stops the run and marks it incomplete. Every
//     repository line sits behind its line number in the user turn, and
//     escape.go first turns every control and format rune and every line
//     or paragraph separator (CR, FF, VT, NEL, U+2028, U+2029, ESC, bidi
//     controls) and every non-UTF-8 byte into a visible escape, so no
//     repository line can render as a fake code line or HYPOTHESIS header.
//     Prompt-injection text stays data and never reaches the system prompt.
//
// The user turn is a "HYPOTHESIS: <class>, source line N, sink line M"
// line built from enums and integers only, a "CODE:" line, the slice's
// escaped lines as "N| text" in file order, and "[slice truncated: ...]"
// when lines were left out or cut. Budgets per tier: S 2048, M 4096, L 8192
// bytes, a hard cap measured after escaping; a line is cut at budget/8.
// Hypotheses that get no slice are listed in SliceReport.NotEvaluated with
// a closed SkipReason: file_not_scanned (the file is in NotScanned with its
// gateway.SkipReason), run_full, line_out_of_range (past the file's end or
// MaxLine) and lines_shifted (redaction joined lines, as a multi-line
// private key does, so the file's numbers would not match; the file is
// also in NotScanned with FileLinesShifted).
//
// Known limits: slicing reads Python only, by names and indentation; it
// follows names within one file and the function around the sink, not
// into helpers in other files or across calls; a guard contributes only
// its first body line; and it over-approximates, since an assignment never
// stops a name from being tracked.
//
// Evaluate (evaluate.go) asks the model about one slice: the tier's system
// prompt, Slice.Text as the user turn and Slice.Redactions for egress.log,
// sent with models.Complete through the caller's client (the gateway in
// production), then Project. Any answer that fails the schema, Validate or
// Project is an error, never a verdict.
//
// Replay fixtures (#95): testdata/replay/<app>/cache holds one recorded
// reply per hypothesis on each testdata/apps app, in the internal/state
// cache format, keyed by the SHA-256 of the exact request body. replay_test.go
// runs every app's vulnerable and safe variants through Slicer.Build and
// Evaluate from those recordings, with no network and no key, and checks
// the verdicts expected.json implies: vulnerable citing the sink line on the
// vulnerable variant, not_vulnerable on the safe twin. The replies are
// synthesized from expected.json, not recorded from a live model, so they
// pin the reader path (slicing, prompt, request, decoding, projection), not
// a model's judgement. They are signed with a fixed public test secret, so a
// real run, which uses the user's own secret, never serves them. A missing,
// torn, edited, foreign or stale recording fails the test (replay_fail_test.go).
// After changing a prompt, the schema, slicing or an app, regenerate them:
//
//	go test ./internal/reader -run TestAppsReplay -update
package reader
