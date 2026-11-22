# ADR 0022: Baseline and accepted risks with an expiry

- **Status:** Proposed
- **Date:** 2026-11-21
- **Deciders:** @Ludocius
- **Amends:** [ADR 0009](0009-scan-and-why-contract.md) (the gate skips suppressed findings; report v1 gains `fingerprint` and `suppression` on a finding; a new command)
- **Changes:** three new stable contracts: the baseline file (`internal/baseline`, version 1), the fingerprint (`creep-fingerprint-v1`), and the CLI flags `--baseline`, `--baseline-write`, `--expires`, `--reason` with the command `creep accept`; report v1 additions; `reader.Slice.Sink`, `scanrun.Finding.Anchor`
- **Fitness function:** the row "A baseline never hides a finding silently" of [architecture.md §9](../architecture.md#9-fitness-functions)

## Context

Teams adopt a scanner only if existing findings do not block every build (#27): only new findings should break CI, and a reviewed risk should be acceptable for a while, not forever. #28 (gate modes) and #29 (the Action, annotations only on new findings) build on it.

Three facts shape the decision:

- The file that says which findings are old has to be committed to the scanned repository so CI can use it. That repository is untrusted (TB1): a hostile pull request can add its own finding to the file.
- Finding IDs are `sink-<n>` in discovery order: adding a file renumbers them. Line numbers move with every edit. Neither can identify a finding across runs.
- A finding's text comes from the repository and may hold a secret. A fingerprint committed to the repository must never be a hash of raw text, since a hash of a short password can be guessed offline.

Constraints: suppression must never apply to `not evaluated`, never turn an incomplete run into a clean one, and never change the exit 4 rules (ADR 0007); JSON v1 changes additively only (maintainer decision, ADR 0009 #26 amendment); standard library only.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Fingerprint = hash of class, path and the redacted sink line (marker numbers and spacing dropped); one JSON file with `baseline` and `accepted` entries, each with an expiry; read only when `--baseline` names it | Stable across line moves; never hashes raw text; one file to review; an attacker's entry shows up in the diff and in every report | Editing the sink line itself, or moving the file, makes the finding new |
| B. Fingerprint = hash of the whole slice | Detects a changed data flow | Any edit inside the handler makes every finding new; the slice depends on the tier's budget |
| C. Fingerprint = class, path and line | Simplest | Every edit above a sink makes it new, which fails the acceptance criterion |
| D. Read `creep-baseline.json` automatically | No flag | A file the pull request adds suppresses its own findings with nobody asking for a baseline |
| E. Baselines without expiry, only accepted risks expire | Matches a plain reading of the issue | A hostile entry written as `baseline` would suppress forever; two rule sets to check |

## Decision

**Option A, with every entry expiring.** It is the one that meets "fingerprints survive unrelated code moves" without hashing anything the repository could hide a secret in.

**Fingerprint** (`baseline.Fingerprint`, domain `creep-fingerprint-v1`): the first 128 bits, as 32 lowercase hex digits, of SHA-256 over the domain, the class, the repository-relative path and an anchor, each length-prefixed. For a finding the reader decided, the anchor is `code:` and the sink line as `redact.File` wrote it (`reader.Slice.Sink`, escaped as the reader escapes it), with each marker's run counter dropped (`<SECRET_GENERIC_API_KEY_3>` becomes `<SECRET_GENERIC_API_KEY>`, since markers are numbered in the order a run meets values) and spacing collapsed. For an optional scanner's finding it is `scanner:` and the runner's line-free key (`scanrun.Finding.Anchor`, a hash of scanner, path and rule or advisory), so a secret gitleaks found is never hashed. Only probable and verified findings get one. Lines moving, code added around the sink, reindenting and other secrets met first keep it (`TestFingerprintGolden`); the sink line changing, the file moving or the class changing make the finding new. A value redaction masks only because an earlier file held it can make a line differ between runs; that makes the finding new, never hidden. Changing the algorithm breaks every committed baseline and needs a new domain and an amendment here.

**Baseline file** (version 1, JSON, read strictly: one value, no unknown field, at most 1 MiB and 4,096 entries, read without following a link or hard link, like `creep.yaml`):

```json
{
  "version": 1,
  "entries": [
    {"kind": "accepted", "fingerprint": "d5966b04d0aeb3a49ad6206d2f4562fa", "class": "sqli", "path": "app/views.py", "expires": "2027-02-19", "reason": "admin-only tool, fix in #12"},
    {"kind": "baseline", "fingerprint": "bd20169bb4b0a6cb092e4d1b18e84d11", "class": "command_injection", "path": "app/views.py", "expires": "2027-02-19"}
  ]
}
```

- Every entry needs `kind` (`baseline` or `accepted`), a fingerprint, a class ID, a path `report.ValidPath` accepts (no `..`, absolute path, drive letter or backslash) and `expires`, a UTC day no more than 365 days ahead (one more day of slack for clocks). An accepted risk needs a `reason`: one printable line of at most 200 bytes, no control or format rune. There are no wildcards: every field is compared exactly. Any invalid field fails the whole file and the scan exits 2 before it opens state or calls a model; errors name the entry and the field, never the value.
- An entry stops suppressing on its `expires` day; the finding is then new and the gate counts it again. An expired entry is counted in the report.
- Each live entry suppresses at most one probable or verified finding with the same fingerprint, class and path. A copied sink needs its own entry. A `not_evaluated` or `discarded` finding is never suppressed, and nothing about coverage changes.

**Scan.** `creep scan --baseline <file>` reads the file; there is no default and no config key, so neither the project file nor any other layer can name or move a baseline. A suppressed finding keeps its status and is still listed: in the text summary (`suppressed: accepted risk until 2027-02-19: <reason>` after the finding, and a `baseline:` line counting suppressed findings by kind, expired entries and live entries that matched no finding), in Markdown (a note on the finding and a Suppressed section listing ID, class, location, kind, expiry and reason), in SARIF (the result's `suppressions`, kind `external`, status `accepted`, the text as justification; `partialFingerprints` `creepFingerprint/v1`; a `creep/baseline` notification) and in JSON (`fingerprint` and `suppression` on the finding). An entry that matched no finding is "not read as fixed": code the run did not evaluate, or an incremental scan left out (#26), can still hold it.

**Gate and exit codes.** The gate skips suppressed findings and nothing else. Incompleteness is decided without looking at suppressions, so exit 4 rules are unchanged: a baseline that suppresses every finding of an incomplete run still exits 4.

**Writing.** `creep scan --baseline <file> --baseline-write` rewrites the file after the run: live accepted risks unchanged, and one `baseline` entry, expiring 90 days later, for each probable or verified finding no accepted risk suppresses; expired entries and old baseline entries are dropped. It writes only from a complete run that read every file except vendor, generated and minified ones (`baseline.Writable`): an incomplete run, or an incremental scan's `unchanged` files, would drop the entries of what it did not read. A refused or failed write prints the reason and never exits 0. `creep accept <id> --expires <n>d --reason <text> [--baseline <file>]` (default `creep-baseline.json`) reads the last scan's `.creep/report.json` as `creep why` does, refuses a finding that is not probable or verified or has no fingerprint, an expiry outside 1d to 365d and a missing or multi-line reason (exit 2), replaces that finding's baseline entry if there is one, and adds the accepted entry. Both write the file through a temporary file in the same directory and a rename, never through a link a repository planted, in a fixed order so the diff shows only what changed.

**A pull request scan must not honor entries its own diff adds.** creep cannot see the diff and reads only the file it is given. So CI reads the baseline from the base commit, not from the pull request's checkout: `git show "$BASE_SHA:creep-baseline.json" > "$RUNNER_TEMP/baseline.json"` and `creep scan --baseline "$RUNNER_TEMP/baseline.json"`. An entry a pull request adds takes effect only after review and merge. The Action (#29) does this; README documents it for other CI. If a CI passes the pull request's own file anyway, every suppression is still listed in the PR's reports, with its reason and expiry, and every entry expires within a year.

**Report v1** gains two optional finding fields, `fingerprint` and `suppression` (`kind`, `expires`, `reason`), published in `docs/schemas/report-v1.json`; `report.ReadJSON` checks them as `report.New` does. The counts (`report.BaselineUse`) are not JSON (`json:"-"`); a finding states its own suppression.

## Consequences

- A team adopts creep with `creep scan --baseline creep-baseline.json --baseline-write` on a complete run, commits the file, and from then on scans with `--baseline`; each entry has to be renewed (re-run the write, or accept with a reason) within 90 days, or its finding blocks again.
- The fingerprint is a contract: changing `SinkAnchor`, the domain or the hashed fields breaks every committed baseline; `TestFingerprintGolden` pins it.
- `internal/baseline` sits in layer 6 and imports only `report`. The CLI computes fingerprints from `reader.Slice.Sink` (the reader's redacted sink line, hashed and never sent or printed) and from `scanrun.Finding.Anchor`.
- #28 and #29 read suppressions from the report: the Action annotates only unsuppressed findings and fails the job on exit 1 or 4.
- Residuals, in the threat model (R24): a CI that passes the pull request's own baseline lets it suppress its own finding until review sees the listed suppression; a planted `.creep/report.json` can make `creep accept <id>` record another fingerprint than the user meant (accept prints the class and location it recorded, and the entry is in the diff); a sink line edited in place keeps no history; a sink of the same class with the same line text in the same file is the same finding to the fingerprint, so removing a baselined sink and adding an identical one elsewhere in that file keeps its entry (a second copy is new).
