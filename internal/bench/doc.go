// Package bench holds creep-bench: a public corpus of vulnerable code with a
// safe twin per case, the scoring that turns scan outcomes into recall,
// false-positive rate and honesty per class and tier, and the replay
// fixtures behind the published numbers (ADR 0030).
//
// It exists because creep asks users to trust what it claims to cover, so
// it must measure that claim the same way: detection on the vulnerable
// twin, false positives on the safe one, and whether the coverage a run
// reports was real.
//
//   - The corpus is data, embedded in the binary: corpus/<id>/case.json
//     names the class, language, the file name the scan sees and, for each
//     twin, the text of its entry and sink lines; vulnerable.src and
//     safe.src hold the code. A marker must sit on exactly one line, so a
//     stale case fails to load. A safe twin has no defensible finding in
//     any class, as calibration's twins (#162): a finding on it counts as a
//     false positive, whatever its class.
//   - The corpus is disjoint from the calibration templates
//     (internal/calibrate/templates), so the bench never measures what
//     calibration tuned on: corpus_test.go fails when a corpus line of 16 or
//     more characters matches any template line, slots read as wildcards.
//   - The package reads no file and calls no model: internal/cli runs each
//     case through the scan pipeline and hands back an Outcome per case,
//     twin and tier. Score is pure and deterministic.
//   - Honesty is the share of runs that claimed the case's class covered
//     and found the planted vulnerability. A run that missed it but said
//     the class was partial or not evaluated is an honest miss; one that
//     said covered is a silent miss.
//   - Fixtures (fixtures/published.json) map the SHA-256 of each request
//     body to the reply the published run got, with the client settings the
//     bodies were built with. creep bench --replay serves only them, with no
//     network and no key. The published set is synthesized (Fixture.
//     Synthesized): an oracle answered from the corpus, so the numbers
//     measure creep's pipeline (inventory, tripwire, planner, slicing,
//     coverage) with a model that is always right, not a model's
//     judgement, until a live run (#36) replaces them.
package bench
