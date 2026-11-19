package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/static"
)

// skipDirs are the top-level directories never walked: version control and
// creep's own state. Only at the root: a nested ".git" or ".creep" is
// walked, so a repository cannot hide code by naming a folder after them.
var skipDirs = map[string]bool{".git": true, stateDir: true}

// repoScan is the static view of the repository: the planner-facing graph,
// the report-only locations, and every source file not evaluated in full.
type repoScan struct {
	graph static.Graph
	locs  static.Locations
	gaps  []report.NotEvaluated
}

// walkRepo extracts every source file under root in lexical order, so the
// same tree gives the same graph. Paths are repo-relative and slash-separated.
// A file static cannot take is listed with its reason and the walk goes on;
// only a walk or context error stops it.
func walkRepo(ctx context.Context, root *os.Root, p *static.Parser) (repoScan, error) {
	ex, proofs := static.NewExtractor(), newVendorProofs(root)
	var gaps []report.NotEvaluated
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
		lang, ok := static.LanguageForPath(rel)
		if !ok {
			if reason, gap := ungrammaredSource(rel, d); gap {
				gaps = append(gaps, report.NotEvaluated{Path: rel, Reason: reason})
			}
			return nil
		}
		if reason, gap := addRepoFile(ctx, ex, p, proofs, rel, lang, d); gap {
			gaps = append(gaps, report.NotEvaluated{Path: rel, Reason: reason})
		}
		return ctx.Err()
	})
	if err != nil {
		return repoScan{}, fmt.Errorf("walk repository: %w", err)
	}
	return repoScan{graph: ex.Graph(), locs: ex.Locations(), gaps: gaps}, nil
}

// maxVendorFileBytes bounds a file of a proven dependency tree, which is
// read for the route test but parsed only when it may hold a route, so it
// may be larger than static.MaxFileBytes (bundled libraries often are).
const maxVendorFileBytes = 32 << 20

// addRepoFile reads one source file and hands it to addFile. A file of a
// proven dependency tree (vendorProofs) that cannot hold a route
// (static.MayHoldRoute) is listed as vendor without parsing, so a large or
// unparseable library file is no gap. Any other file, a proven one that may
// hold a route included, goes through addFile like first-party code: a mark
// is a repository file the author can plant, so it never hides a route
// (#213). static then lists the file as vendor only if it parsed cleanly
// and holds no route; a proven declaration file only needs to hold no route.
func addRepoFile(ctx context.Context, ex *static.Extractor, p *static.Parser, proofs *vendorProofs, rel string, lang static.Language, d fs.DirEntry) (report.SkipReason, bool) {
	if !d.Type().IsRegular() {
		return report.SkipNotRegular, true
	}
	why, err := static.IgnoreReason(rel, nil)
	proven := err == nil && why == static.IgnoredVendor && proofs.proven(rel)
	limit := int64(static.MaxFileBytes)
	if proven {
		limit = maxVendorFileBytes
	}
	src, err := readInRoot(proofs.root, rel, limit)
	switch {
	case errors.Is(err, errFileTooLarge):
		return report.SkipTooLarge, true
	case err != nil:
		return report.SkipReadFailed, true
	case proven && !static.MayHoldRoute(lang, src):
		return addIgnored(ex, rel, why)
	}
	return addFile(ctx, ex, p, rel, lang, src, proven)
}

// addFile extracts one file into ex and says whether, and why, the file was
// not evaluated in full. A name static refuses (such as a:b.py, which it
// reads as a drive letter) is listed, never dropped and never fatal. So is
// a name report.New would refuse on a finding, such as a\b.py on Unix. A
// declaration file of a proven tree (proven) goes to AddDeclaration, which
// lists it as vendor when it holds no route even if it does not parse.
func addFile(ctx context.Context, ex *static.Extractor, p *static.Parser, rel string, lang static.Language, src []byte, proven bool) (report.SkipReason, bool) {
	if !report.ValidPath(rel) {
		return report.SkipInvalidPath, true
	}
	if _, err := static.IgnoreReason(rel, src); err != nil {
		return report.SkipInvalidPath, true
	}
	add, ok := extractorFor(ex, lang, proven && static.IsDeclaration(rel))
	if !ok {
		return report.SkipUnsupported, true
	}
	tree, err := p.Parse(ctx, lang, src)
	switch {
	case errors.Is(err, static.ErrFileTooLarge):
		return report.SkipTooLarge, true
	case err != nil:
		return report.SkipParseFailed, true
	}
	err = add(rel, tree, src)
	switch {
	case errors.Is(err, static.ErrGraphFull):
		return report.SkipTruncated, true
	case err != nil:
		return report.SkipInvalidPath, true
	}
	return fileOutcome(ex.Graph())
}

// extractorFor picks the extractor for a grammar: Flask and FastAPI for
// Python, Express for JavaScript, TypeScript and TSX. A grammar with no
// extractor is unsupported, never parsed and dropped. A TypeScript
// declaration file of a proven tree (vendorDeclaration) goes to
// AddDeclaration.
func extractorFor(ex *static.Extractor, lang static.Language, vendorDeclaration bool) (func(string, *static.Tree, []byte) error, bool) {
	switch {
	case lang == static.Python:
		return ex.AddPython, true
	case lang == static.TypeScript && vendorDeclaration:
		return ex.AddDeclaration, true
	case lang == static.JavaScript || lang == static.TypeScript || lang == static.TSX:
		return ex.AddJavaScript, true
	}
	return nil, false
}

// fileOutcome reports why the file just added was not evaluated in full:
// left out (static believed its vendor, generated or minified mark because
// it holds no route) or only partly extracted.
func fileOutcome(g static.Graph) (report.SkipReason, bool) {
	f := g.Files[len(g.Files)-1]
	switch {
	case f.Ignored != 0:
		return ignoredReason(f.Ignored), true
	case f.Truncated:
		return report.SkipTruncated, true
	case f.SyntaxError:
		return report.SkipSyntaxError, true
	}
	return "", false
}

func addIgnored(ex *static.Extractor, rel string, why static.Ignored) (report.SkipReason, bool) {
	if err := ex.AddIgnored(rel, why); err != nil {
		return report.SkipInvalidPath, true
	}
	return ignoredReason(why), true
}

// ignoredReason maps static's reason to the report's. Each is left out by
// design (report.SkipReason.ByDesign) and believed only with evidence
// (pentest P4, #213): a vendor file is listed unread only when its package
// manager's mark exists (vendorProofs); any other is read, and static lists
// it only when it parsed cleanly and holds no route.
func ignoredReason(why static.Ignored) report.SkipReason {
	switch why {
	case static.IgnoredVendor:
		return report.SkipVendor
	case static.IgnoredGenerated:
		return report.SkipGenerated
	case static.IgnoredMinified:
		return report.SkipMinified
	}
	return report.SkipInvalidPath
}
