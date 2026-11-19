package static

import (
	"path"
	"strings"
)

// VendorEvidence names the file that must exist, as a regular file with
// exactly that name, for name to be believed part of a dependency tree. A
// directory name alone is the author's say-so (pentest P4, #213); a package
// manager leaves a mark, and the mark only vouches for what its packages
// ship. Names are case-sensitive and exact, and the first such directory in
// the path decides:
//
//   - node_modules/<pkg>/ or node_modules/@scope/<pkg>/: <pkg>/package.json,
//     for JavaScript and TypeScript files, native addon sources (C and C++)
//     and front-end components (.vue, .svelte);
//   - venv/ or .venv/: pyvenv.cfg in that directory, for Python files and
//     C extension sources, Cython (.pyx) included.
//
// The mark is a file too, so it proves only that a caller may skip parsing
// a file that cannot hold a route (MayHoldRoute, MayHoldAnyRoute); a file
// that may is still parsed or, for a language static has no grammar for,
// listed as unsupported. The Extractor believes the vendor path only when
// the file holds no route (addSource). Go's vendor/modules.txt and PHP's
// composer.json vouch for nothing, and no mark vouches for a server-side
// language other than Python and JavaScript (#261).
//
// ok is false when no such directory holds the file or the mark does not
// vouch for its kind; the caller then reads the file like first-party code.
func VendorEvidence(name string) (evidence string, ok bool) {
	rel, err := repoRelative(name)
	if err != nil {
		return "", false
	}
	segs := strings.Split(rel, "/")
	lang, _ := LanguageForPath(rel)
	ext := strings.ToLower(path.Ext(rel))
	for i := range len(segs) - 1 {
		switch segs[i] {
		case "node_modules":
			return packageEvidence(segs, i, lang, ext)
		case "venv", ".venv":
			return strings.Join(segs[:i+1], "/") + "/pyvenv.cfg", lang == Python || nativeSourceExts[ext] || ext == ".pyx"
		}
	}
	return "", false
}

// nativeSourceExts and componentExts are the closed set of ungrammared
// sources a mark vouches for besides its own language (#261): Python C
// extensions and Node native addons, and npm front-end components. None of
// them can serve a Flask, FastAPI or Express route by itself.
var (
	nativeSourceExts = map[string]bool{".c": true, ".h": true, ".cc": true, ".cpp": true, ".cxx": true, ".hpp": true}
	componentExts    = map[string]bool{".vue": true, ".svelte": true}
)

// packageEvidence is the package.json of the package under
// node_modules/ at segs[i] that holds the file, scoped or not.
func packageEvidence(segs []string, i int, lang Language, ext string) (string, bool) {
	vouched := lang == JavaScript || lang == TypeScript || lang == TSX || nativeSourceExts[ext] || componentExts[ext]
	if !vouched {
		return "", false
	}
	end := i + 2 // node_modules/<pkg>
	if strings.HasPrefix(segs[i+1], "@") {
		end++ // node_modules/@scope/<pkg>
	}
	if end >= len(segs) { // the file itself would be the package
		return "", false
	}
	return strings.Join(segs[:end], "/") + "/package.json", true
}
