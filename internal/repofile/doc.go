// Package repofile holds the rules creep applies to repository files and to
// programs found on the host that do not depend on any language.
//
// It exists because these rules outlived internal/static (ADR 0017): the
// scan, the optional scanners and the sandbox all need them, and none of
// them parses code. It imports no other creep package, so any layer may
// use it.
//
//   - IgnoreReason reads the marks an author can put on a file's bytes: a
//     generator marker in the first five lines ("@generated" as a word, or
//     "generated" with "do not edit" or "do not modify", in any case and
//     any comment syntax) or a minified shape (nine tenths of the bytes on
//     lines over 500 bytes; no file name, such as *.min.*, counts). No rule
//     names a language, a package manager or a directory (#366,
//     TestRulesNameNoEcosystem). A mark is the author's say-so (pentest P4,
//     #213): the caller believes it only for a file discovery read in full
//     with no candidate, so a file with anything in it is evaluated
//     whatever its mark (ADR 0017).
//
//   - GitIgnore matches the repository's own .gitignore and info/exclude
//     patterns in git's syntax, so vendor and generated trees are told by
//     what the repository ignores, not by directory names. The caller
//     lists a file as vendor only when it is ignored and the git index
//     tracks nothing in its tree: committed code is always read.
//
//     Repo-relative names are split at the host's separator, like the walk
//     that made them: '\' separates on Windows only (#194).
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
