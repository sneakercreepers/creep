// Package repofile holds the rules creep applies to repository files and to
// programs found on the host that do not depend on any language.
//
// It exists because these rules outlived internal/static (ADR 0017): the
// scan, the optional scanners and the sandbox all need them, and none of
// them parses code. It imports no other creep package, so any layer may
// use it.
//
//   - IgnoreReason reads the marks an author can put on a file: a vendor
//     directory name, a generator header (Go's "Code generated ... DO NOT
//     EDIT.", "@generated" as the first word, or protoc's header, in the
//     leading comments only; a block comment counts only when it closes on
//     a line of its own, so "/* @generated */ var x;" is code), or a
//     minified JavaScript or TypeScript shape (nine tenths of the bytes on
//     lines over 500 bytes; no file name, *.min.js or *-min.js, counts).
//     Names are split at the host's separator, like the walk that made
//     them: '\' separates on Windows only, and elsewhere is a byte of a
//     legal file name (#194). A mark is the author's say-so (pentest P4,
//     #213): the caller lists a vendor file unread only when VendorEvidence
//     names a package-manager mark that exists, and believes a generated or
//     minified mark only for a file discovery read in full with no
//     candidate, so no opt-back-in is needed: a file with anything in it is
//     evaluated whatever its mark (ADR 0017).
//
//   - EscapeLines makes repository lines inert before a prompt shows them,
//     so no line can pass for a second line, a header or a terminal
//     command. The reader's slices and discover's batches use this one rule.
//
//   - DetectScanners looks the optional external scanners (gitleaks,
//     osv-scanner, semgrep) up on PATH and never runs them (ADR 0010). The
//     first match decides, and one in a relative PATH entry is refused. A
//     match is resolved to its final path (links and junctions followed,
//     \\?\ removed), and OutsideRepo refuses it when that path or a
//     directory above it is the repository or the current directory,
//     compared by file identity (ADR 0013). internal/scanrun and
//     internal/sandbox run only such final paths.
package repofile
