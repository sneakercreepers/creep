// Package baseline reads, matches and writes creep's baseline file: the
// findings a team has chosen not to block on, each with an expiry (ADR 0022).
//
// It exists because only new findings should break CI, while the file that
// says which findings are old lives in the scanned repository, where a
// hostile pull request can edit it. Everything that keeps that file from
// hiding a finding silently lives here:
//
//   - A finding is matched by its fingerprint (Fingerprint), a hash of its
//     class, its path and its redacted sink line with the run's marker
//     numbers and the line's spacing dropped, or of an optional scanner's
//     rule key. Lines moving, or code added around the sink, keep it; the
//     sink line itself changing, or the file moving, makes the finding new.
//     It never hashes raw text: the line comes from redact.File output.
//   - An entry suppresses one finding with the same fingerprint, class and
//     path, and only a probable or verified one: never a not-evaluated or
//     discarded finding, and never a coverage gap. There are no wildcards:
//     every field is compared exactly, and a malformed field, or a key
//     spelled otherwise or repeated, fails the whole file (the caller exits
//     2), so what a reviewer reads in the diff is what creep reads.
//   - Every entry expires, at most MaxDays ahead; an expired entry stops
//     suppressing, so its finding is new again. An accepted risk needs a
//     reason. The file is bounded (MaxEntries, and the caller reads at most
//     1 MiB).
//   - Apply reports how the file was used (report.BaselineUse), so every
//     suppression is listed in the text summary, Markdown and SARIF, and on
//     the finding in JSON; an entry that matched nothing is counted, never
//     read as fixed.
//   - Writable refuses to write a baseline from a run that did not read
//     every file it could (anything listed not evaluated except vendor,
//     generated and minified files), so a partial run never drops the
//     entries of what it skipped.
//
// The package never reads the clock: callers pass today's date.
package baseline
