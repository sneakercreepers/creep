package static

import (
	"path"
	"strings"
)

// VendorEvidence names the file that must exist, as a regular file, for
// name to be believed a dependency, so a caller may list it as vendor
// without reading it. A directory name alone is the author's say-so
// (pentest P4, #213); a package manager leaves a mark, and the mark only
// vouches for its own language. Names are case-sensitive and exact, and
// the first such directory in the path decides:
//
//   - node_modules/<pkg>/ or node_modules/@scope/<pkg>/: <pkg>/package.json,
//     for JavaScript and TypeScript files;
//   - venv/ or .venv/: pyvenv.cfg in that directory, for Python files;
//   - vendor/: modules.txt in it for Go files, composer.json next to it
//     for PHP files.
//
// ok is false when no such directory holds the file or the language does
// not match; the caller then reads the file, and the Extractor believes a
// vendor path only for a file with no route (addSource).
func VendorEvidence(name string) (evidence string, ok bool) {
	rel, err := repoRelative(name)
	if err != nil {
		return "", false
	}
	segs := strings.Split(rel, "/")
	ext := strings.ToLower(path.Ext(rel))
	lang, _ := LanguageForPath(rel)
	for i := range len(segs) - 1 {
		dir := strings.Join(segs[:i+1], "/")
		switch segs[i] {
		case "node_modules":
			return packageEvidence(segs, i, lang)
		case "venv", ".venv":
			return dir + "/pyvenv.cfg", lang == Python
		case "vendor":
			return vendorDirEvidence(dir, ext)
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

func vendorDirEvidence(dir, ext string) (string, bool) {
	switch ext {
	case ".go":
		return dir + "/modules.txt", true
	case ".php":
		return path.Join(path.Dir(dir), "composer.json"), true
	}
	return "", false
}
