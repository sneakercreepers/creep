package main

import (
	"fmt"
	"path"
	"sort"
)

// linkProven lists third-party modules whose import graph reaches package
// net or a process start, each with the one main-module package that may
// import them. The net and process reach checks skip such an import there
// because internal/tools/linkcheck proves, on the linked binary of every
// release target, that no third-party code creep links reaches a function
// that opens a connection or starts a program (ADR 0027). Any other
// package importing the module still fails both checks.
var linkProven = map[string]string{
	"github.com/modelcontextprotocol/go-sdk": "internal/mcp",
}

// linkExempt reports an import of a linkProven module by the one package
// allowed to import it. The module comes from the listing, not from the
// import path, so a look-alike path gets no exemption.
func linkExempt(modPath string, pkgs map[string]listedPackage, importer, imp string) bool {
	m := pkgs[imp].Module
	if m == nil || m.Main {
		return false
	}
	allowed, ok := linkProven[m.Path]
	return ok && importer == path.Join(modPath, allowed)
}

// reachProblems runs the transitive net and process-start checks over one
// listing of the import graph.
func reachProblems(cfg config) ([]string, error) {
	mf, err := readModFile(cfg.root)
	if err != nil {
		return nil, err
	}
	pkgs, err := listPackages(cfg.root)
	if err != nil {
		return nil, err
	}
	starters, err := thirdPartyStarters(pkgs)
	if err != nil {
		return nil, err
	}
	return append(checkNetReach(mf.Module.Path, pkgs), checkProcessReach(mf.Module.Path, pkgs, starters)...), nil
}

// checkNetReach reports main-module packages outside the gateway whose code or
// tests pull in package net through any chain of imports, such as expvar or
// a third-party client. Main-module packages are checked on their own, so the
// walk stops at them.
func checkNetReach(modPath string, pkgs map[string]listedPackage) []string {
	gateway := path.Join(modPath, gatewayDir)
	var problems []string
	for _, p := range sortedMainPackages(pkgs) {
		if underPath(p.ImportPath, gateway) {
			continue
		}
		roots := append(append(append([]string{}, p.Imports...), p.TestImports...), p.XTestImports...)
		for _, root := range roots {
			if isMain(pkgs, root) || linkExempt(modPath, pkgs, p.ImportPath, root) {
				continue
			}
			if reachesNet(pkgs, root, map[string]bool{}) {
				problems = append(problems, fmt.Sprintf("%s reaches package net through %s (AGENTS.md invariant 1)", p.ImportPath, root))
			}
		}
	}
	return problems
}

func reachesNet(pkgs map[string]listedPackage, imp string, seen map[string]bool) bool {
	if imp == "net" {
		return true
	}
	if seen[imp] || isMain(pkgs, imp) {
		return false
	}
	seen[imp] = true
	for _, next := range pkgs[imp].Imports {
		if reachesNet(pkgs, next, seen) {
			return true
		}
	}
	return false
}

func isMain(pkgs map[string]listedPackage, imp string) bool {
	m := pkgs[imp].Module
	return m != nil && m.Main
}

func sortedMainPackages(pkgs map[string]listedPackage) []listedPackage {
	var mains []listedPackage
	for _, p := range pkgs {
		if p.Module != nil && p.Module.Main {
			mains = append(mains, p)
		}
	}
	sort.Slice(mains, func(i, j int) bool { return mains[i].ImportPath < mains[j].ImportPath })
	return mains
}
