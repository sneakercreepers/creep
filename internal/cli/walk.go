package cli

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/report"
)

// skipDirs are the top-level directories never walked: version control and
// creep's own state. Only at the root: a nested ".git" or ".creep" is
// walked, so a repository cannot hide code by naming a folder after them.
var skipDirs = map[string]bool{".git": true, stateDir: true}

// repoFiles is what the walk found: the files discovery is given, in
// lexical order, and the files it lists without handing them over.
type repoFiles struct {
	paths []string // repo-relative, slash-separated, lexical
	gaps  []report.NotEvaluated
}

// sources is how many of the files could be source: at most this many go
// to the model whole (the scan-start notice, ADR 0017 D1).
func (f repoFiles) sources() int {
	n := 0
	for _, p := range f.paths {
		if discover.MaybeSource(p) {
			n++
		}
	}
	return n
}

// walkRepo lists every file under root in lexical order, so the same tree
// gives the same requests. Every regular file goes to discovery, which
// decides from the name and bytes what is source (ADR 0017), except a file
// listed by entryGap. Only a walk error stops it; past a deadline on ctx
// no vendor tree is proven (vendorProofs), so the files go to discovery,
// which lists them unread.
func walkRepo(ctx context.Context, root *os.Root) (repoFiles, error) {
	proofs := newVendorProofs(ctx, root)
	var files repoFiles
	err := fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[rel] {
				return fs.SkipDir
			}
			return nil
		}
		reason, send := entryGap(root, rel, d, proofs)
		switch {
		case send:
			files.paths = append(files.paths, rel)
		case reason != "":
			files.gaps = append(files.gaps, report.NotEvaluated{Path: rel, Reason: reason})
		}
		return nil
	})
	if err != nil {
		return repoFiles{}, fmt.Errorf("walk repository: %w", err)
	}
	return files, nil
}

// entryGap says whether a file goes to discovery or, when it does not and
// could be source, why it is listed:
//
//   - a link or special file that could hold source is listed by linkGap:
//     creep never reads through it;
//   - a name report.New would refuse on a finding (such as a\b.py on Unix
//     or a:b.py) is invalid_path, never dropped and never fatal;
//   - a file of an installed dependency tree (vendorProofs: its package
//     manager's mark exists and git tracks nothing in the tree) is vendor,
//     by design, without being read.
//
// A file that cannot be source is neither sent nor listed.
func entryGap(root *os.Root, rel string, d fs.DirEntry, proofs *vendorProofs) (report.SkipReason, bool) {
	if !d.Type().IsRegular() {
		return linkGap(root, rel, proofs), false
	}
	if report.ValidPath(rel) && !proofs.proven(rel) {
		return "", true
	}
	if !discover.MaybeSource(rel) {
		return "", false
	}
	if !report.ValidPath(rel) {
		return report.SkipInvalidPath, false
	}
	return report.SkipVendor, false
}

// linkGap lists a link or special file the walk does not follow when it
// could hold source: its name is a source name, or it may be a directory
// (mayBeDirectory), whatever its name (#214). One in an installed tree is
// vendor, like the tree's files; any other is not_regular, which makes the
// run incomplete (ADR 0009).
func linkGap(root *os.Root, rel string, proofs *vendorProofs) report.SkipReason {
	if !discover.SourceName(rel) && !mayBeDirectory(root, rel) {
		return ""
	}
	if report.ValidPath(rel) && proofs.proven(rel) {
		return report.SkipVendor
	}
	return report.SkipNotRegular
}

// mayBeDirectory reports whether the entry at rel may be a directory: the
// root resolves it to one, or cannot resolve it. The root never leaves the
// repository, so a link whose target is outside it, missing, a loop or an
// absolute path, and a Windows junction, all of which the root refuses,
// cannot be told from a directory without following it out; each counts
// as one (fail closed).
// Only the target's metadata is read, never its contents.
func mayBeDirectory(root *os.Root, rel string) bool {
	info, err := root.Stat(rel)
	return err != nil || info.IsDir()
}
