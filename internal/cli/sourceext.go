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
	".cfm": true, ".pyx": true,
}

// ungrammaredSource lists a source file static cannot parse: a link or
// special file as not_regular, a file of a proven dependency tree that its
// mark vouches for and that holds no route word as vendor, anything else as
// unsupported_language. A mark vouches only for C and C++ sources and
// front-end components (static.VendorEvidence, #261), never for another
// server-side language, and a planted mark cannot hide embedded Python or
// JavaScript route code (static.MayHoldAnyRoute). Files with other
// extensions are not source and are not listed.
func ungrammaredSource(proofs *vendorProofs, rel string, d fs.DirEntry) (report.SkipReason, bool) {
	if !otherSourceExts[strings.ToLower(path.Ext(rel))] {
		return "", false
	}
	if !d.Type().IsRegular() {
		return report.SkipNotRegular, true
	}
	why, err := static.IgnoreReason(rel, nil)
	if err != nil {
		return report.SkipInvalidPath, true
	}
	if why == static.IgnoredVendor && proofs.proven(rel) && routeFree(proofs, rel) {
		return ignoredReason(why), true
	}
	return report.SkipUnsupported, true
}

// routeFree reads a proven ungrammared file and reports whether no route
// word is in it. A file it cannot read, or one too large, is not
// route-free.
func routeFree(proofs *vendorProofs, rel string) bool {
	src, err := readInRoot(proofs.root, rel, maxVendorFileBytes)
	if err != nil {
		return false
	}
	return !static.MayHoldAnyRoute(src)
}

// shadowsTrustedModule reports whether a first-party Python file would be
// imported in place of a package static trusts with an app (uvicorn.run,
// flask_cors.CORS): Python searches the script's own directory first, so
// a repository uvicorn.py makes uvicorn.run(app) code static does not
// read. A file under a vendor directory is the installed package.
func shadowsTrustedModule(rel string) bool {
	why, err := static.IgnoreReason(rel, nil)
	return err == nil && why != static.IgnoredVendor && static.ShadowsTrustedModule(rel)
}
