// Package state keeps creep's run state on disk as JSONL, so runs can be
// recorded, replayed with no network, and resumed after an interruption.
//
// It exists so that tests and CI runs are deterministic and free (model
// responses replay from disk) without a database dependency. Layout under the
// state directory (./.creep in the scanned repository for creep scan):
//
//	lock                     empty; an open Run holds an OS lock on it
//	runs/<id>/events.jsonl   append-only event log of one run
//	cache/<sha256>.json      one recorded model response, shared across runs
//	calibrations/<sha256>.json  one model calibration (internal/calibrate),
//	                         kept in a store under the user's cache directory
//
// The run directory is also where the gateway writes egress.log (Run.Dir).
//
// What it guarantees:
//   - Every line carries a version field "v". Readers accept unknown fields,
//     so new fields are additive; a newer "v" fails closed. A committed v1
//     fixture (testdata/v1) must keep decoding with no unknown fields, so a
//     removed or retyped field fails the tests.
//   - State is never trusted because of where it sits: .creep may arrive
//     inside the scanned repository. Every line ends with an HMAC-SHA256
//     ("mac") keyed by a per-user secret kept outside every repository
//     (state.key in os.UserConfigDir, read by OpenUser). A run line's MAC
//     also covers its
//     run ID. A line without a valid MAC is ErrUnauthenticated (and
//     ErrCorrupt); replay, Load and Resume fail on it. A planted response
//     or a planted "complete" run is therefore never served or believed.
//   - Live mode never serves a cache entry that is not a valid recording and
//     never stops on one: a planted, torn, multi-line or oversized file is a
//     miss and the model's answer is recorded over it; an entry or cache
//     directory that is a link, directory or FIFO is a miss too, left alone,
//     and the answer goes unrecorded. Replay fails closed on all of them, so
//     the caller marks the run incomplete. Only an entry a newer creep signed
//     (ErrUnsupportedVersion) is an error in live.
//   - Committed fixtures (testdata/v1, the reader's testdata/replay) are
//     signed with a fixed, public test key that _test.go files pass to
//     OpenWithSecret, so go test ./... replays them with no user key.
//     OpenWithSecret returns ErrTestOnly unless the binary was built by go
//     test (testing.Testing), however a caller reaches it, so production
//     code opens stores only through OpenUser, which takes no secret.
//     Inside this package a type-checked test (TestKeysComeOnlyFromOpen)
//     keeps every key coming from open, and no non-test file may hold the
//     test key in any common encoding. OpenUser refuses a state.key holding
//     a fixed pattern, so copying the test key there fails closed.
//   - One run at a time per state directory: NewRun and Resume take an
//     exclusive OS lock (flock on Unix, an unshared handle on Windows) held
//     until Run.Close, and fail at once with ErrLocked instead of waiting, so
//     two creep processes never interleave appends. The OS drops the lock when
//     a process dies, so a crash never leaves the directory locked. Load
//     takes no lock.
//   - Run IDs must match the exact form NewRun writes, so no alias (Windows
//     drops a trailing dot or space) reaches a run.
//   - Files are 0600 and directories 0700. Cache entries are written to a
//     temporary file, synced and renamed, so a reader never sees half of one.
//     Events are appended with one write and an fsync per line.
//   - Reading is bounded (MaxLineBytes, MaxResponseBytes) and fails closed: a
//     torn, oversized, out-of-order or unknown line is ErrCorrupt, never
//     skipped. Files are opened without following a swapped-in link and
//     without blocking on a FIFO.
//   - A run is complete only when its log ends with an "end" line whose
//     outcome is "complete". A run that stopped early (a crash, or
//     redact.ErrRunFull reported by the caller as OutcomeIncomplete) loads as
//     incomplete, so it can never be read back as a clean scan.
//
// What it does not do: redact. Events hold only IDs and enums (Step and
// Reason are checked against an ID alphabet), and the cache holds model
// responses exactly as the gateway returned them for already redacted
// requests. Callers must not store anything else.
package state
