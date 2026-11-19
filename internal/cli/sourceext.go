package cli

import (
	"io/fs"
	"path"
	"strings"

	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/static"
)

// otherSourceExts are source languages static has no grammar for, lowercase
// with the dot. A file with one of them could hold a route and a sink, so it
// is listed as unsupported_language and the run is incomplete (ADR 0009),
// never silently skipped. The list is closed data: a new entry is a reviewed
// change. It names server-side languages and server templates that handle
// requests; shell, config, markup and data files are not listed, because
// they do not serve routes and would make every repository incomplete.
var otherSourceExts = map[string]bool{
	".go": true, ".php": true, ".phtml": true, ".java": true, ".jsp": true,
	".kt": true, ".kts": true, ".scala": true, ".groovy": true, ".clj": true,
	".rb": true, ".erb": true, ".cs": true, ".cshtml": true, ".razor": true,
	".aspx": true, ".vb": true, ".fs": true, ".rs": true, ".ex": true,
	".exs": true, ".erl": true, ".swift": true, ".dart": true, ".pl": true,
	".pm": true, ".lua": true, ".c": true, ".h": true, ".cc": true,
	".cpp": true, ".cxx": true, ".hpp": true, ".vue": true, ".svelte": true,
	".cfm": true,
}

// ungrammaredSource lists a source file static cannot parse: a link or
// special file as not_regular, a file of an installed dependency tree
// (vendorProofs: its mark exists and git tracks nothing in the tree) as
// vendor by design whatever its language, anything else as
// unsupported_language. Files with other extensions are not source and are
// not listed.
func ungrammaredSource(rel string, d fs.DirEntry, proofs *vendorProofs) (report.SkipReason, bool) {
	if !otherSourceExts[strings.ToLower(path.Ext(rel))] {
		return "", false
	}
	if !d.Type().IsRegular() {
		return report.SkipNotRegular, true
	}
	why, err := static.IgnoreReason(rel, nil)
	switch {
	case err != nil:
		return report.SkipInvalidPath, true
	case why == static.IgnoredVendor && proofs.proven(rel):
		return report.SkipVendor, true
	}
	return report.SkipUnsupported, true
}
