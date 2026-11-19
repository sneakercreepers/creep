package cli

import (
	"cmp"
	"slices"

	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/repofile"
	"github.com/sneakercreepers/creep/internal/report"
)

// discoveryGaps lists every file discovery did not read in full, with its
// report reason (ADR 0017 D2). A file read in full with no candidate keeps
// the vendor, generated or minified mark it carries: listed by design, never
// a gap. A file with a candidate is evaluated whatever its mark (#213).
func discoveryGaps(res discover.Result, paths []string, marks map[string]repofile.Ignored) []report.NotEvaluated {
	touched := filesWithCandidates(res)
	var gaps []report.NotEvaluated
	for i, path := range paths {
		if i >= len(res.Files) {
			break // discoverRepo refuses a Result of another length
		}
		f := res.Files[i]
		reason := fileReason(f)
		if reason == "" && f.Coverage == discover.CoverageReadFull && !touched[f.ID] {
			reason = markReason(marks[path])
		}
		if reason != "" {
			gaps = append(gaps, report.NotEvaluated{Path: path, Reason: reason})
		}
	}
	return gaps
}

// filesWithCandidates marks every file that holds a sink or a proposed
// entry point (a file-level route exists only to hold sinks).
func filesWithCandidates(res discover.Result) map[discover.FileID]bool {
	touched := map[discover.FileID]bool{}
	for _, s := range res.Sinks {
		touched[s.File] = true
	}
	for _, r := range res.Routes {
		touched[r.File] = true
	}
	return touched
}

func markReason(why repofile.Ignored) report.SkipReason {
	switch why {
	case repofile.IgnoredVendor:
		return report.SkipVendor
	case repofile.IgnoredGenerated:
		return report.SkipGenerated
	case repofile.IgnoredMinified:
		return report.SkipMinified
	}
	return ""
}

// fileReason is why discovery did not read a file in full, or "". A file
// at the tripwire's hit cap is truncated. Coverage that is neither read in
// full nor not source with no known reason fails closed as send_failed.
func fileReason(f discover.File) report.SkipReason {
	switch {
	case f.TripwireCut && f.Reason == discover.ReasonNone:
		return report.SkipTruncated
	case f.Coverage == discover.CoverageReadFull, f.Coverage == discover.CoverageNotSource:
		return ""
	}
	if r, ok := skipReason(f.Reason); ok {
		return r
	}
	return report.SkipSendFailed
}

// skipReason maps a discovery reason by explicit switch, as plannermap.go
// does for the planner: discoverymap_test.go fails when discover gains a
// reason this file does not name.
func skipReason(r discover.Reason) (report.SkipReason, bool) {
	switch r {
	case discover.ReasonReadFailed:
		return report.SkipReadFailed, true
	case discover.ReasonTooLarge:
		return report.SkipTooLarge, true
	case discover.ReasonLineTooLong:
		return report.SkipLineTooLong, true
	case discover.ReasonRedactFailed:
		return report.SkipRedactFailed, true
	case discover.ReasonLinesShifted:
		return report.SkipLinesShifted, true
	case discover.ReasonRunFull:
		return report.SkipRunFull, true
	case discover.ReasonBudget:
		return report.SkipBudget, true
	case discover.ReasonSendFailed:
		return report.SkipSendFailed, true
	case discover.ReasonParseFailed:
		return report.SkipParseFailed, true
	case discover.ReasonTruncated:
		return report.SkipTruncated, true
	}
	return "", false
}

// discoverySummary is what Markdown and the text summary say about
// discovery: whole-file egress, the inventory and each failed batch.
func discoverySummary(res discover.Result) report.Discovery {
	d := report.Discovery{Inventory: inventoryCounts(res.Files)}
	batches := map[uint32]*report.BatchNote{}
	for _, f := range res.Files {
		if f.Batch == 0 {
			continue
		}
		d.WholeFiles++
		cause, failed := batchCause(f)
		if !failed {
			continue
		}
		n := batches[f.Batch]
		if n == nil {
			n = &report.BatchNote{Batch: int(f.Batch), Cause: cause}
			batches[f.Batch] = n
		}
		n.Files++
	}
	for _, n := range batches {
		d.Batches = append(d.Batches, *n)
	}
	slices.SortFunc(d.Batches, func(a, b report.BatchNote) int { return cmp.Compare(a.Batch, b.Batch) })
	return d
}

// batchCause names why a sent file is parse_failed: its batch missed the
// canary, or the reply was invalid.
func batchCause(f discover.File) (report.BatchCause, bool) {
	switch {
	case f.Coverage == discover.CoverageCanaryMissed:
		return report.CauseCanaryMissed, true
	case f.Reason == discover.ReasonParseFailed:
		return report.CauseInvalidReply, true
	}
	return "", false
}

// inventoryCounts counts files per language, manifest and container ID,
// each kind sorted by ID.
func inventoryCounts(files []discover.File) []report.InventoryCount {
	var out []report.InventoryCount
	add := func(kind, id string, set bool) {
		if !set {
			return
		}
		i := slices.IndexFunc(out, func(c report.InventoryCount) bool { return c.Kind == kind && c.ID == id })
		if i < 0 {
			out = append(out, report.InventoryCount{Kind: kind, ID: id})
			i = len(out) - 1
		}
		out[i].Files++
	}
	for _, f := range files {
		add(report.InventoryLanguage, f.Language.String(), f.Language != 0)
		add(report.InventoryManifest, f.Manifest.String(), f.Manifest != 0)
		add(report.InventoryContainer, f.Container.String(), f.Container != 0)
	}
	kinds := []string{report.InventoryLanguage, report.InventoryManifest, report.InventoryContainer}
	slices.SortFunc(out, func(a, b report.InventoryCount) int {
		return cmp.Or(cmp.Compare(slices.Index(kinds, a.Kind), slices.Index(kinds, b.Kind)), cmp.Compare(a.ID, b.ID))
	})
	return out
}
