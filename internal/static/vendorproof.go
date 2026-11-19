package static

import (
	"strings"
)

// VendorEvidence names the file that must exist, as a regular file with
// exactly that name, for name to be believed part of a dependency tree. A
// directory name alone is the author's say-so (pentest P4, #213); a package
// manager leaves a mark, and the mark only vouches for its own language.
// Names are case-sensitive and exact, and the first such directory in the
// path decides:
//
//   - node_modules/<pkg>/ or node_modules/@scope/<pkg>/: <pkg>/package.json,
//     for JavaScript and TypeScript files;
//   - venv/ or .venv/: pyvenv.cfg in that directory, for Python files.
//
// The mark is a file too, so it proves only that a caller may skip parsing
// a file that cannot hold a route (MayHoldRoute); a file that may is still
// parsed, and the Extractor believes the vendor path only when it holds no
// route (addSource). Go's vendor/modules.txt and PHP's composer.json vouch
// for nothing: static cannot check those languages for routes.
//
// ok is false when no such directory holds the file or the language does
// not match; the caller then reads the file like first-party code.
func VendorEvidence(name string) (evidence string, ok bool) {
	rel, err := repoRelative(name)
	if err != nil {
		return "", false
	}
	segs := strings.Split(rel, "/")
	lang, _ := LanguageForPath(rel)
	for i := range len(segs) - 1 {
		switch segs[i] {
		case "node_modules":
			return packageEvidence(segs, i, lang)
		case "venv", ".venv":
			return strings.Join(segs[:i+1], "/") + "/pyvenv.cfg", lang == Python
		}
	}
	return "", false
}

// packageEvidence is the package.json of the package under
// node_modules/ at segs[i] that holds the file, scoped or not.
func packageEvidence(segs []string, i int, lang Language) (string, bool) {
	if lang != JavaScript && lang != TypeScript && lang != TSX {
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
