package cli

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/report"
)

// skipDirs are the top-level entries never walked or listed, whatever
// their type: version control and creep's own state. A link or junction
// there, or a worktree's .git file (it holds a local absolute path), is
// skipped like the directory. Only at the root: a nested ".git" or
// ".creep" is walked, so a repository cannot hide code by naming a folder
// after them.
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
// decides from the name and bytes what it reads (ADR 0017, #366), except a
// file listed by entryGap or, once the walk is over, by linkGap. Only a walk
// error stops it; past a deadline on ctx no vendor tree is proven
// (vendorProofs) and no link is read, so the files go to discovery, which
// lists them unread, and the links are listed.
func walkRepo(ctx context.Context, root *os.Root) (repoFiles, error) {
	w := repoWalk{proofs: newVendorProofs(ctx, root), tree: newWalkedTree()}
	if err := fs.WalkDir(root.FS(), ".", w.visit); err != nil {
		return repoFiles{}, fmt.Errorf("walk repository: %w", err)
	}
	resolveLinks(ctx, root, &w.files, w.links, w.tree, w.proofs)
	return w.files, nil
}

// repoWalk is the state of one walkRepo.
type repoWalk struct {
	proofs *vendorProofs
	tree   *walkedTree
	files  repoFiles
	links  []pendingLink // gaps decided after the walk, in files.gaps order
}

func (w *repoWalk) visit(rel string, d fs.DirEntry, err error) error {
	if err != nil {
		return err
	}
	if skipDirs[rel] && d.IsDir() {
		return fs.SkipDir
	}
	if skipDirs[rel] {
		return nil
	}
	if !d.IsDir() && !d.Type().IsRegular() {
		w.links = append(w.links, pendingLink{gap: len(w.files.gaps), rel: rel, mode: d.Type()})
		w.files.gaps = append(w.files.gaps, report.NotEvaluated{Path: rel})
		return nil
	}
	w.tree.add(rel, d.IsDir())
	if d.IsDir() {
		return nil
	}
	if reason, send := entryGap(rel, w.proofs); !send {
		w.files.gaps = append(w.files.gaps, report.NotEvaluated{Path: rel, Reason: reason})
		return nil
	}
	w.files.paths = append(w.files.paths, rel)
	return nil
}

// entryGap says whether a regular file goes to discovery or, when it does
// not, why it is listed; every file is one or the other (#366):
//
//   - a name report.New would refuse on a finding (such as a\b.py on Unix
//     or a:b.py) is invalid_path, never dropped and never fatal, or
//     not_code when its name is a text format discovery never opens;
//   - a file of an ignored, untracked tree (vendorProofs: the repository's
//     ignore patterns cover it and git tracks nothing in the tree) is
//     vendor, by design, without being read.
//
// Links and special files are listed by linkGap: creep never reads
// through them.
func entryGap(rel string, proofs *vendorProofs) (report.SkipReason, bool) {
	switch {
	case !report.ValidPath(rel) && discover.MaybeSource(rel):
		return report.SkipInvalidPath, false
	case !report.ValidPath(rel):
		return report.SkipNotCode, false
	case proofs.proven(rel):
		return report.SkipVendor, false
	}
	return "", true
}
