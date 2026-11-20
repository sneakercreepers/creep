package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// modFile is the subset of `go mod edit -json` the budget needs. Letting the
// go command parse go.mod avoids hand-parsing quirks such as `require(`.
type modFile struct {
	Module  struct{ Path string }
	Require []modRequire
	Replace []modReplace
	Tool    []struct{ Path string }
}

type modReplace struct {
	Old, New struct{ Path, Version string }
}

type modRequire struct {
	Path     string
	Indirect bool
}

func readModFile(root string) (modFile, error) {
	out, err := goOutput(root, "mod", "edit", "-json")
	if err != nil {
		return modFile{}, err
	}
	var mf modFile
	if err := json.Unmarshal(out, &mf); err != nil {
		return modFile{}, fmt.Errorf("parse go mod edit -json: %w", err)
	}
	if mf.Module.Path == "" {
		return modFile{}, fmt.Errorf("go.mod has no module path")
	}
	return mf, nil
}

// directModules returns the required modules go.mod does not mark
// `// indirect`. The marks are exact because `make check` runs
// `go mod tidy -diff`, which fails when a used module is marked indirect.
func directModules(reqs []modRequire) []string {
	var mods []string
	for _, r := range reqs {
		if !r.Indirect {
			mods = append(mods, r.Path)
		}
	}
	return mods
}

// toolModules returns the module behind each `tool` directive, which needs an
// ADR like a direct dependency even when go.mod marks it `// indirect`. A tool
// inside the main module needs none; a tool no required module provides is a
// problem, since its code would come from nowhere the allowlist sees.
func toolModules(mf modFile) ([]string, []string) {
	var mods, problems []string
	for _, t := range mf.Tool {
		if underPath(t.Path, mf.Module.Path) {
			continue
		}
		mod := providingModule(mf.Require, t.Path)
		if mod == "" {
			problems = append(problems, fmt.Sprintf("go.mod tool %s: no required module provides it", t.Path))
			continue
		}
		mods = append(mods, mod)
	}
	return mods, problems
}

// providingModule returns the longest required module path that pkg sits under.
func providingModule(reqs []modRequire, pkg string) string {
	best := ""
	for _, r := range reqs {
		if underPath(pkg, r.Path) && len(r.Path) > len(best) {
			best = r.Path
		}
	}
	return best
}

// checkReplaces reports versioned replace directives that swap in another
// module, unless that module has its own allowlist entry and ADR. A
// replacement by another version of the same module keeps its author and is
// verified by go.sum; local paths are checkWorkspace's.
func checkReplaces(replaces []modReplace, allow map[string]string, adrExists func(string) bool) []string {
	var problems []string
	for _, r := range replaces {
		if r.New.Version == "" || r.New.Path == r.Old.Path {
			continue
		}
		adr, ok := allow[r.New.Path]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("go.mod replaces %s with %s %s, which has no ADR in the allowlist", r.Old.Path, r.New.Path, r.New.Version))
		case !adrExists(adr):
			problems = append(problems, fmt.Sprintf("go.mod replaces %s with %s: ADR %s does not exist", r.Old.Path, r.New.Path, adr))
		}
	}
	return problems
}

// underPath reports whether pkg is root or a package nested below it.
func underPath(pkg, root string) bool {
	return pkg == root || strings.HasPrefix(pkg, root+"/")
}
