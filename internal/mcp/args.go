package mcp

import (
	"fmt"
	"strings"

	"github.com/sneakercreepers/creep/internal/report"
)

// Bounds on what a caller may ask for. The caller is an agent that may be
// under prompt injection, so every argument is checked here, before the
// backend sees it, and nothing it sends is ever echoed back unescaped.
const (
	// maxChanged is far more files than a pull request or a commit touches.
	maxChanged = 1000
	// maxPathBytes is the git index's path cap (gitindex.MaxPathBytes).
	maxPathBytes = 4096
	// maxPage and defaultPage bound one findings page.
	maxPage     = 200
	defaultPage = 50
	// maxOffset is far past any report scan writes.
	maxOffset = 1 << 20
)

// ScanArgs are the scan tool's arguments.
type ScanArgs struct {
	Changed []string `json:"changed" jsonschema:"repository-relative paths of the changed files with forward slashes, 1 to 1000 (git diff --name-only)"`
}

// FindingsArgs are the findings tool's arguments.
type FindingsArgs struct {
	Status string `json:"status,omitempty" jsonschema:"only findings with this status: verified, probable, discarded or not_evaluated"`
	Offset int    `json:"offset,omitempty" jsonschema:"how many matching findings to skip"`
	Limit  int    `json:"limit,omitempty" jsonschema:"how many findings to return, 1 to 200 (default 50)"`
}

// WhyArgs are the why tool's arguments.
type WhyArgs struct {
	ID string `json:"id" jsonschema:"the finding ID, as the scan and findings tools list it"`
}

// checkChanged refuses an empty or oversized list and any entry that is
// not a clean repository-relative path: absolute, a drive letter, a
// backslash, "..", "." or an empty segment, so no entry can name a file
// outside the repository. A NUL is refused too: the backend joins the
// list with NULs, as git's -z does. The backend checks the list again
// with the --changed rules.
func checkChanged(paths []string) error {
	switch {
	case len(paths) == 0:
		return fmt.Errorf("changed lists no file; scan takes the changed files only, run creep scan from the CLI for a full scan")
	case len(paths) > maxChanged:
		return fmt.Errorf("changed lists %d files, more than %d", len(paths), maxChanged)
	}
	for i, p := range paths {
		switch {
		case len(p) > maxPathBytes:
			return fmt.Errorf("changed entry %d is over %d bytes", i+1, maxPathBytes)
		case strings.ContainsRune(p, 0):
			return fmt.Errorf("changed entry %d holds a NUL byte", i+1)
		case !report.ValidPath(p):
			return fmt.Errorf("changed entry %d (%s) is not a clean path inside the repository, relative with forward slashes", i+1, quote(p))
		}
	}
	return nil
}

// page checks a findings request and returns its status filter, offset
// and limit.
func (a FindingsArgs) page() (report.Status, int, int, error) {
	status := report.Status(a.Status)
	switch status {
	case "", report.StatusVerified, report.StatusProbable, report.StatusDiscarded, report.StatusNotEvaluated:
	default:
		return "", 0, 0, fmt.Errorf("status %s: want verified, probable, discarded or not_evaluated", quote(a.Status))
	}
	if a.Offset < 0 || a.Offset > maxOffset {
		return "", 0, 0, fmt.Errorf("offset %d: want 0 to %d", a.Offset, maxOffset)
	}
	limit := a.Limit
	if limit == 0 {
		limit = defaultPage
	}
	if limit < 1 || limit > maxPage {
		return "", 0, 0, fmt.Errorf("limit %d: want 1 to %d", a.Limit, maxPage)
	}
	return status, a.Offset, limit, nil
}

// maxQuoted bounds an argument echoed in an error.
const maxQuoted = 80

// quote shows an untrusted string in an error: cut to maxQuoted bytes and
// with every non-printable rune escaped, so it cannot break a line, hide
// text behind a bidi override or pose as protocol output.
func quote(s string) string {
	cut := ""
	if len(s) > maxQuoted {
		s, cut = s[:maxQuoted], "..."
	}
	return `"` + report.Visible(s) + `"` + cut
}
