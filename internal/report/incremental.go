package report

import (
	"fmt"
	"io"
)

// Incremental is the scope of a scan limited to changed files (`creep scan
// --changed`, #26). JSON carries that scope file by file: every file that
// could be source and was left out because the list does not name it is
// listed `unchanged`, by design. This struct adds what only the text
// summary, Markdown and SARIF state: that the run was incremental, and how
// many listed paths named no file the scan reads. It holds counts only,
// never a path, and is not part of the JSON contract.
type Incremental struct {
	On      bool
	Listed  int // distinct paths in the list
	Missing int // listed paths that are no file the walk hands to discovery
}

func checkIncremental(i Incremental) error {
	switch {
	case i.Listed < 0, i.Missing < 0, i.Missing > i.Listed:
	case !i.On && (i.Listed != 0 || i.Missing != 0):
	default:
		return nil
	}
	return fmt.Errorf("%w: incremental scope %+v", ErrInvalid, i)
}

// Text is the incremental mark, or "" for a full scan. files are the
// report's not-evaluated files, from which it counts the unchanged ones.
func (i Incremental) Text(files []NotEvaluated) string {
	if !i.On {
		return ""
	}
	unchanged := 0
	for _, f := range files {
		if f.Reason == SkipUnchanged {
			unchanged++
		}
	}
	return fmt.Sprintf("incremental scan (--changed): %s scanned, %s no file creep reads (deleted, a directory, a link, or never walked); "+
		"%s not evaluated (reason unchanged), and code they hold that a changed file reaches is not evaluated either",
		plural(i.Listed-i.Missing, "listed file", "listed files"), plural(i.Missing, "listed path is", "listed paths are"),
		plural(unchanged, "unchanged file", "unchanged files"))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// writeIncremental is Markdown's incremental mark, under the run status.
func writeIncremental(w io.Writer, text string) {
	if text == "" {
		return
	}
	fmt.Fprintf(w, "> **Incremental scan.** %s.\n\n", text)
}

// incrementalNotifications is SARIF's note on an incremental scan.
func incrementalNotifications(text string) []sarifNotification {
	if text == "" {
		return nil
	}
	return []sarifNotification{{
		Descriptor: sarifDescriptor{ID: "creep/incremental"},
		Level:      "note",
		Message:    sarifMessage{Text: text},
	}}
}
