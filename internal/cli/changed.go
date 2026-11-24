package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/gitindex"
	"github.com/sneakercreepers/creep/internal/report"
)

// maxChangedBytes caps the --changed list: about 160,000 paths of 100
// bytes, far more than any pull request or commit touches.
const maxChangedBytes = 16 << 20

// changedList is the --changed list: the repository paths an incremental
// scan is limited to (#26). creep never runs git, so the list comes from
// the operator, who builds it with git (`git diff --name-only -z <base>`
// in CI, `git diff --cached --name-only -z` before a commit). Its names are
// the repository's, so they are untrusted: the list only selects among the
// files the walk found, and is never opened or joined into a path.
type changedList struct {
	paths map[string]bool // in lower case: scope matches without regard to case
}

// readChangedList reads the list at path, or returns nil when --changed
// was not given. The file is opened as --config is (a regular file, no
// FIFO, no UNC share or /proc path) and read whole, at most
// maxChangedBytes.
func readChangedList(path string) (*changedList, error) {
	if path == "" {
		return nil, nil
	}
	data, err := readCappedFile(openConfig, "--changed", path, maxChangedBytes)
	if err != nil {
		return nil, err
	}
	return parseChangedList(data)
}

// changedList is the list creep mcp built in memory, or --changed.
func (e env) changedList() (*changedList, error) {
	if e.changed != nil {
		return e.changed, nil
	}
	return readChangedList(e.opts.changed)
}

// parseChangedList reads one path per line, or, when the data holds a NUL
// byte, one per NUL (git's -z). Blank entries are skipped, and repeats
// count once, case variants included. Any entry that is not a clean
// repository-relative path fails the whole list: a list the scan cannot
// read exactly would scan a scope nobody chose.
func parseChangedList(data []byte) (*changedList, error) {
	sep := byte('\n')
	if bytes.IndexByte(data, 0) >= 0 {
		sep = 0
	}
	list := &changedList{paths: map[string]bool{}}
	// Cut, not Split, and a repeat skipped before it is copied: a 16 MiB
	// list of short entries would otherwise allocate millions of slice
	// headers and strings before the first check.
	for i := 1; len(data) > 0; i++ {
		var entry []byte
		entry, data, _ = bytes.Cut(data, []byte{sep})
		if sep == '\n' {
			entry = bytes.TrimSuffix(entry, []byte{'\r'})
		}
		if len(entry) == 0 || list.paths[string(entry)] {
			continue
		}
		p := string(entry)
		if err := checkChangedPath(p, sep); err != nil {
			return nil, fmt.Errorf("--changed entry %d: %w", i, err)
		}
		list.paths[strings.ToLower(p)] = true
	}
	return list, nil
}

// checkChangedPath refuses an entry no walked file can have: one over the
// git index's path cap, one git quoted (it does so for unusual names
// unless -z is given, so the quoted form would miss the real file), and
// one report.ValidPath refuses (absolute, a drive letter, a backslash,
// "..", "." or an empty segment).
func checkChangedPath(p string, sep byte) error {
	switch {
	case len(p) > gitindex.MaxPathBytes:
		return fmt.Errorf("a path over %d bytes", gitindex.MaxPathBytes)
	case sep == '\n' && strings.HasPrefix(p, `"`):
		return fmt.Errorf("%q is quoted the way git quotes unusual names; list the paths with git's -z (NUL-separated)", p)
	case !report.ValidPath(p):
		return fmt.Errorf("%q is not a clean path relative to the repository root with forward slashes", p)
	}
	return nil
}

// scope splits the walked files: the files the list names go to the scan,
// and every other file that could be source is listed unchanged, by
// design. Names match without regard to case: on a case-insensitive file
// system git's index can spell a name differently from the disk, and
// scanning one file more never hides a change. The walk's own gaps stay
// as they are, so a link, a refused name or a vendor file is listed as in
// a full scan. A listed path that is no walked file (deleted, a directory,
// a link, under the root .git or .creep) is only counted. A nil list scans
// every file.
func (c *changedList) scope(files repoFiles) (repoFiles, report.Incremental) {
	if c == nil {
		return files, report.Incremental{}
	}
	matched := map[string]bool{}
	out := repoFiles{gaps: slices.Clone(files.gaps)}
	for _, p := range files.paths {
		key := strings.ToLower(p)
		switch {
		case c.paths[key]:
			out.paths = append(out.paths, p)
			matched[key] = true
		case discover.MaybeSource(p):
			out.gaps = append(out.gaps, report.NotEvaluated{Path: p, Reason: report.SkipUnchanged})
		}
	}
	return out, report.Incremental{On: true, Listed: len(c.paths), Missing: len(c.paths) - len(matched)}
}

// printIncremental states an incremental scan's scope; nothing for a full
// scan. It holds counts only, never a path.
func printIncremental(w io.Writer, rep *report.Report) {
	if text := rep.Incremental.Text(rep.Coverage.NotEvaluated); text != "" {
		fmt.Fprintln(w, text)
	}
}

// changedCommands are the commands --changed limits; any other command
// refuses it rather than run a scope nobody asked for.
var changedCommands = map[string]bool{"scan": true, "estimate": true, "resume": true}

func checkChangedFlag(command string, opts globalOptions) error {
	switch {
	case !opts.explicit["changed"]:
		return nil
	case opts.changed == "":
		return errors.New("--changed needs a file listing the changed paths; leave the flag out to scan every file")
	case !changedCommands[command]:
		return fmt.Errorf("--changed limits only scan, resume and estimate, not %s", command)
	}
	return nil
}
