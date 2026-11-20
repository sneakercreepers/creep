package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"sort"
	"strings"
)

// listedPackage is the subset of `go list -json` the reachability checks need.
type listedPackage struct {
	ImportPath     string
	Standard       bool
	Dir            string
	GoFiles        []string
	CgoFiles       []string
	IgnoredGoFiles []string
	Imports        []string
	TestImports    []string
	XTestImports   []string
	Module         *struct {
		Path string
		Main bool
	}
}

// reachGOOS are the release targets (.goreleaser.yaml). The import graph
// differs per platform, so the reach checks walk the union of all three
// rather than only the host's.
var reachGOOS = []string{"linux", "darwin", "windows"}

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

// listPackages merges `go list -deps -test -json ./...` over every reachGOOS.
func listPackages(root string) (map[string]listedPackage, error) {
	merged := map[string]listedPackage{}
	for _, goos := range reachGOOS {
		out, err := goOutputEnv(root, []string{"GOOS=" + goos}, "list", "-deps", "-test", "-json", "./...")
		if err != nil {
			return nil, fmt.Errorf("GOOS=%s: %w", goos, err)
		}
		pkgs, err := decodePackages(out)
		if err != nil {
			return nil, fmt.Errorf("GOOS=%s: %w", goos, err)
		}
		for name, p := range pkgs {
			merged[name] = mergePackage(merged[name], p)
		}
	}
	return merged, nil
}

// mergePackage unions the file and import lists of one package listed for two platforms.
func mergePackage(have, p listedPackage) listedPackage {
	if have.ImportPath == "" {
		return p
	}
	have.GoFiles = union(have.GoFiles, p.GoFiles)
	have.CgoFiles = union(have.CgoFiles, p.CgoFiles)
	have.IgnoredGoFiles = union(have.IgnoredGoFiles, p.IgnoredGoFiles)
	have.Imports = union(have.Imports, p.Imports)
	have.TestImports = union(have.TestImports, p.TestImports)
	have.XTestImports = union(have.XTestImports, p.XTestImports)
	return have
}

// union appends the entries of b missing from a, keeping a's order.
func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// decodePackages reads the JSON stream `go list -json` prints, dropping the
// test variants ("p [p.test]", "p.test") that -test adds.
func decodePackages(data []byte) (map[string]listedPackage, error) {
	pkgs := map[string]listedPackage{}
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var p listedPackage
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			return pkgs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parse go list -json: %w", err)
		}
		if strings.Contains(p.ImportPath, " ") || strings.HasSuffix(p.ImportPath, ".test") {
			continue
		}
		pkgs[p.ImportPath] = p
	}
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
			if isMain(pkgs, root) {
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
