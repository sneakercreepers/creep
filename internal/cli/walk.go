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
	ex := static.NewExtractor()
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
		if reason, gap := addRepoFile(ctx, ex, p, root, rel, lang, d); gap {
			gaps = append(gaps, report.NotEvaluated{Path: rel, Reason: reason})
		}
		return ctx.Err()
	})
	if err != nil {
		return repoScan{}, fmt.Errorf("walk repository: %w", err)
	}
	return repoScan{graph: ex.Graph(), locs: ex.Locations(), gaps: gaps}, nil
}

// addRepoFile reads one source file and hands it to addFile. Vendor files
// are listed from their path alone, without reading them.
func addRepoFile(ctx context.Context, ex *static.Extractor, p *static.Parser, root *os.Root, rel string, lang static.Language, d fs.DirEntry) (report.SkipReason, bool) {
	if !d.Type().IsRegular() {
		return report.SkipNotRegular, true
	}
	if why, err := static.IgnoreReason(rel, nil); err == nil && why == static.IgnoredVendor {
		return addIgnored(ex, rel, why)
	}
	src, err := readInRoot(root, rel, static.MaxFileBytes)
	switch {
	case errors.Is(err, errFileTooLarge):
		return report.SkipTooLarge, true
	case err != nil:
		return report.SkipReadFailed, true
	}
	return addFile(ctx, ex, p, rel, lang, src)
}

// addFile extracts one file into ex and says whether, and why, the file was
// not evaluated in full. A name static refuses (such as a:b.py, which it
// reads as a drive letter) is listed, never dropped and never fatal.
func addFile(ctx context.Context, ex *static.Extractor, p *static.Parser, rel string, lang static.Language, src []byte) (report.SkipReason, bool) {
	why, err := static.IgnoreReason(rel, src)
	if err != nil {
		return report.SkipInvalidPath, true
	}
	if why != 0 {
		return addIgnored(ex, rel, why)
	}
	if lang != static.Python {
		return report.SkipUnsupported, true
	}
	tree, err := p.Parse(ctx, lang, src)
	switch {
	case errors.Is(err, static.ErrFileTooLarge):
		return report.SkipTooLarge, true
	case err != nil:
		return report.SkipParseFailed, true
	}
	err = ex.AddPython(rel, tree, src)
	switch {
	case errors.Is(err, static.ErrGraphFull):
		return report.SkipTruncated, true
	case err != nil:
		return report.SkipInvalidPath, true
	}
	return partialFile(ex.Graph())
}

// partialFile reports why the file just added was only partly extracted.
func partialFile(g static.Graph) (report.SkipReason, bool) {
	f := g.Files[len(g.Files)-1]
	switch {
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
	switch why {
	case static.IgnoredVendor:
		return report.SkipVendor, true
	case static.IgnoredGenerated:
		return report.SkipGenerated, true
	case static.IgnoredMinified:
		return report.SkipMinified, true
	}
	return report.SkipInvalidPath, true
}

// byDesign reports a file left out on purpose (vendor, generated or
// minified code): listed, but not a gap that makes the run partial.
func byDesign(r report.SkipReason) bool {
	return r == report.SkipVendor || r == report.SkipGenerated || r == report.SkipMinified
}
