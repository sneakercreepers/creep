package report

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

func checkFindings(in []Finding) ([]Finding, error) {
	out := make([]Finding, len(in))
	seen := make(map[string]bool, len(in))
	for i, f := range in {
		if err := checkFinding(f, seen); err != nil {
			return nil, err
		}
		out[i] = f
	}
	sort.SliceStable(out, func(i, j int) bool { return findingLess(out[i], out[j]) })
	return out, nil
}

func checkFinding(f Finding, seen map[string]bool) error {
	switch {
	case !idPattern.MatchString(f.ID):
		return fmt.Errorf("%w: finding ID %q", ErrInvalid, f.ID)
	case seen[f.ID]:
		return fmt.Errorf("%w: duplicate finding ID %q", ErrInvalid, f.ID)
	case !idPattern.MatchString(f.Class):
		return fmt.Errorf("%w: finding %s: class %q", ErrInvalid, f.ID, f.Class)
	case !ValidPath(f.Path):
		return fmt.Errorf("%w: finding %s: path %q", ErrInvalid, f.ID, f.Path)
	case f.Line < 0:
		return fmt.Errorf("%w: finding %s: line %d", ErrInvalid, f.ID, f.Line)
	case f.Reason != "" && !idPattern.MatchString(f.Reason):
		return fmt.Errorf("%w: finding %s: reason %q", ErrInvalid, f.ID, f.Reason)
	case f.Confidence < 0 || f.Confidence > maxConfidence:
		return fmt.Errorf("%w: finding %s: confidence %d", ErrInvalid, f.ID, f.Confidence)
	}
	for _, r := range f.Evidence {
		if r.Start < 1 || r.End < r.Start {
			return fmt.Errorf("%w: finding %s: evidence %d-%d", ErrInvalid, f.ID, r.Start, r.End)
		}
	}
	if _, ok := statusRank[f.Status]; !ok {
		return fmt.Errorf("%w: finding %s: status %q", ErrInvalid, f.ID, f.Status)
	}
	seen[f.ID] = true
	return nil
}

// ValidPath reports whether p can name a finding's file: relative to the
// repository root, slash-separated and clean (no empty, "." or ".."
// segment, no trailing slash), with no backslash and no drive letter. Any
// other path could make a SARIF location resolve outside %SRCROOT%, and
// Windows reads a backslash as a separator and "C:" as a volume.
func ValidPath(p string) bool {
	switch {
	case p == "" || p == "." || path.Clean(p) != p:
		return false
	case path.IsAbs(p) || p == ".." || strings.HasPrefix(p, "../"):
		return false
	case strings.ContainsRune(p, '\\'):
		return false
	}
	return !hasDriveLetter(p)
}

// hasDriveLetter reports a leading "C:" in any case, as Windows reads it.
func hasDriveLetter(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	c := p[0] | 0x20 // ASCII lower case
	return 'a' <= c && c <= 'z'
}

func findingLess(a, b Finding) bool {
	if ra, rb := statusRank[a.Status], statusRank[b.Status]; ra != rb {
		return ra < rb
	}
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	return a.ID < b.ID
}

// checkClasses validates each class and, for an incomplete run, downgrades
// covered to partial: a run that stopped early cannot claim full coverage.
func checkClasses(in []ClassCoverage, incomplete bool) ([]ClassCoverage, error) {
	out := make([]ClassCoverage, len(in))
	seen := make(map[string]bool, len(in))
	for i, c := range in {
		if err := checkClass(c, seen); err != nil {
			return nil, err
		}
		if incomplete && c.Status == ClassCovered {
			c.Status = ClassPartial
		}
		c.CILow, c.CIHigh = wilson(c.Detected, c.Tasks)
		out[i] = c
	}
	return out, nil
}

func checkClass(c ClassCoverage, seen map[string]bool) error {
	switch {
	case !idPattern.MatchString(c.Class):
		return fmt.Errorf("%w: class %q", ErrInvalid, c.Class)
	case seen[c.Class]:
		return fmt.Errorf("%w: duplicate class %q", ErrInvalid, c.Class)
	case c.Status != ClassCovered && c.Status != ClassPartial && c.Status != ClassNotEvaluated:
		return fmt.Errorf("%w: class %s: status %q", ErrInvalid, c.Class, c.Status)
	case c.Tasks < 0 || c.Detected < 0 || c.Detected > c.Tasks:
		return fmt.Errorf("%w: class %s: detected %d of %d", ErrInvalid, c.Class, c.Detected, c.Tasks)
	}
	seen[c.Class] = true
	return nil
}

// checkNotEvaluated keeps scan order and drops exact repeats (SARIF
// notifications must be unique); a path is never dropped otherwise.
func checkNotEvaluated(in []NotEvaluated) ([]NotEvaluated, error) {
	out := make([]NotEvaluated, 0, len(in))
	seen := make(map[NotEvaluated]bool, len(in))
	for i, n := range in {
		if !skipReasons[n.Reason] {
			return nil, fmt.Errorf("%w: not-evaluated file %d: reason %q", ErrInvalid, i, n.Reason)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}
