package repofile

import "strings"

// VendorEvidence names the mark a package manager leaves at the top of the
// dependency tree that holds name: the file that must exist, as a regular
// file with exactly that name, for name to be believed part of an install.
// A directory name alone is the author's say-so (pentest P4, #213). Names
// are case-sensitive and exact, and the first such directory in the path
// decides:
//
//   - node_modules/<pkg>/ or node_modules/@scope/<pkg>/: <pkg>/package.json;
//   - venv/ or .venv/: pyvenv.cfg in that directory.
//
// The tree is the mark's directory. Go's vendor/modules.txt and PHP's
// composer.json vouch for nothing: `go mod vendor` output is committed by
// design, and composer.json is the project's own manifest, not a mark an
// install leaves.
//
// A mark is a file the author can plant, so it is evidence only together
// with proof that the tree was installed rather than committed: the caller
// must also check that version control tracks nothing in the tree. With
// both, the mark vouches for every file of the tree, whatever its
// language. ok is false when no such directory holds the file; the caller
// then reads the file like first-party code.
func VendorEvidence(name string) (evidence string, ok bool) {
	rel, err := repoRelative(name)
	if err != nil {
		return "", false
	}
	segs := strings.Split(rel, "/")
	for i := range len(segs) - 1 {
		switch segs[i] {
		case "node_modules":
			return packageEvidence(segs, i)
		case "venv", ".venv":
			return strings.Join(segs[:i+1], "/") + "/pyvenv.cfg", true
		}
	}
	return "", false
}

// packageEvidence is the package.json of the package under
// node_modules/ at segs[i] that holds the file, scoped or not.
func packageEvidence(segs []string, i int) (string, bool) {
	end := i + 2 // node_modules/<pkg>
	if strings.HasPrefix(segs[i+1], "@") {
		end++ // node_modules/@scope/<pkg>
	}
	if end >= len(segs) { // the file itself would be the package
		return "", false
	}
	return strings.Join(segs[:end], "/") + "/package.json", true
}
