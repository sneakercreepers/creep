// Package discover finds a repository's entry points and sinks in any
// language: an inventory by file name and bytes, a lexical tripwire, and
// model discovery over whole redacted files, combined by union only.
//
// It exists so that creep needs no per-language code (ADR 0017). The
// model proposes, creep validates, and nothing a model says can lower a
// candidate's risk or remove one:
//
//   - Inventory (inventory.go, inventory.txt) classifies each path by its
//     name, or the "#!" line of an extensionless file, into a source
//     language, a manifest or a container file, from one embedded table.
//     A source file with a NUL in its first 8 KiB is binary, not source.
//
//   - The tripwire (tripwire.go, tripwire.tsv) matches one cross-language
//     table of plain sink signatures on each line of the redacted file:
//     linear, no parser, comments and strings included. Each hit is a
//     candidate with a line and a planner sink kind. A file reaching
//     MaxTripwireHits is TripwireCut.
//
//   - Discovery (discover.go, batch.go) sends whole redact.File output in
//     batches of up to MaxFilesPerBatch files that fit the tier's budget;
//     a file that fits no batch is too_large, never split. Every call goes
//     through models.Complete and the caller's client, the gateway in
//     production. Each file is a "FILE n (language, count lines):" header
//     and its lines as "N| text", escaped (repofile.EscapeLines), so no repository
//     line can pass for a header. Prompts are versioned data per tier
//     (prompts/, PromptVersion) with token-budget tests.
//
//   - The reply (answer.go) is a closed schema of file numbers, line
//     spans, enums and entry indexes, with no free text: models refuses
//     unknown, duplicate and case-variant keys, then Validate and
//     inBounds check every proposal against its section. Any invalid
//     proposal makes the reply invalid, and the batch's files are
//     parse_failed. A reply at a per-file cap marks the file truncated.
//
//   - Each batch carries a canary (canary.go): a synthetic Express router
//     whose token and position come from an HMAC of the batch under the
//     run's Seed. A reply that does not report its entry point and its
//     sink makes every file of the batch canary_missed (parse_failed in
//     the report). Canary proposals never reach the Result.
//
//   - Union (union.go): tripwire hits and model sinks merge by line and
//     kind; neither removes a candidate. creep assigns every ID, in path,
//     line and kind order. Every route has AllMethods and Authenticated
//     false, and every sink DynamicArg true, Parameterized false and
//     Indirect false: the planner's worst case. A sink with no proposed
//     entry point around it goes to one FileLevel route per file. Auth
//     spans are kept only to widen the reader's slice.
//
//   - Samples (ADR 0024): with Reruns (--stability N) every batch goes to
//     Model and to each rerun with the same prompt; each reply is checked
//     and its canary found on its own, its proposals join the union, and a
//     file any sample failed stays failed. Sink.SeenBy records which
//     samples named a candidate (every one for a tripwire hit); it labels
//     findings and is never read by planning.
//
// Result holds only IDs, enums, line numbers and booleans (text_test.go),
// so it can fill planner.Input and reader.Target without carrying text.
// Each File says how it was read (Coverage) and why not in full (Reason,
// an existing report v1 not-evaluated reason).
//
// Replay fixtures (testdata/replay/<app>) hold one recorded reply per
// testdata app, synthesized from its expected.json, in the internal/state
// cache format; regenerate them with:
//
//	go test ./internal/discover -run TestAppsReplay -update
//
// They pin the discovery path, not a model's judgement, so the recall
// they give is not a quality measure; a store recorded from a real model
// can be scored by the same test (-fixtures).
package discover
