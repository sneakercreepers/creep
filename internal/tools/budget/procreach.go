package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"slices"
	"strconv"
)

// The process-start reach check is deliberately conservative, not exact:
//   - it works per package, so reaching a package that can start a program
//     counts even when the starting function is never called;
//   - in the standard library only os/exec starts programs (os and syscall
//     hold the primitives every package reaches; their direct use is watched
//     by checkProcessUses), so reaching os/exec counts, and with it go/build,
//     go/importer and every other package that imports it;
//   - a third-party package counts when any of its files, other platforms'
//     included, imports a raw-call package or names os.StartProcess, whether
//     or not it ever runs a program;
//   - a main-module package under execAllowed (internal/tools) counts when
//     reached from outside it; other main-module packages are checked on
//     their own, so the walk stops at them, as for package net.
const processStdlib = "os/exec"

// rawCallImports can start a program without os/exec: system calls, cgo,
// linkname through unsafe, plugins, or the go command via go/build.
var rawCallImports = []string{"syscall", "golang.org/x/sys", "unsafe", "C", "runtime/cgo", "plugin", "os/exec", "go/build", "go/importer"}

// thirdPartyStarters returns each package outside the standard library and
// the main module that could start a program, with the reason.
func thirdPartyStarters(pkgs map[string]listedPackage) (map[string]string, error) {
	starters := map[string]string{}
	for name, p := range pkgs {
		if p.Standard || (p.Module != nil && p.Module.Main) {
			continue
		}
		why, err := starterReason(p)
		if err != nil {
			return nil, err
		}
		if why != "" {
			starters[name] = why
		}
	}
	return starters, nil
}

// starterReason parses every Go file of p, whatever its build constraints.
func starterReason(p listedPackage) (string, error) {
	if p.Dir == "" {
		return "", fmt.Errorf("package %s: go list gave no source directory", p.ImportPath)
	}
	fset := token.NewFileSet()
	for _, name := range slices.Concat(p.GoFiles, p.CgoFiles, p.IgnoredGoFiles) {
		file, err := parser.ParseFile(fset, filepath.Join(p.Dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return "", fmt.Errorf("package %s: parse %s: %w", p.ImportPath, name, err)
		}
		for _, spec := range file.Imports {
			imp, err := strconv.Unquote(spec.Path.Value)
			if err == nil && isRawCallImport(imp) {
				return fmt.Sprintf("%s imports %q", name, imp), nil
			}
		}
		for _, use := range selectorUses(file) {
			if use == "os.StartProcess" || use == "os.*" {
				return fmt.Sprintf("%s uses %s", name, use), nil
			}
		}
	}
	return "", nil
}

func isRawCallImport(imp string) bool {
	return slices.ContainsFunc(rawCallImports, func(root string) bool { return underPath(imp, root) })
}

// checkProcessReach reports main-module packages that may not start programs
// but whose code or tests reach a package that can.
func checkProcessReach(modPath string, pkgs map[string]listedPackage, starters map[string]string) []string {
	gateway := path.Join(modPath, gatewayDir)
	var problems []string
	for _, p := range sortedMainPackages(pkgs) {
		if underPath(p.ImportPath, gateway) {
			continue
		}
		problems = append(problems, rootReach(modPath, pkgs, starters, sourceFile{Pkg: p.ImportPath}, p.Imports)...)
		tests := sourceFile{Pkg: p.ImportPath, Test: true}
		problems = append(problems, rootReach(modPath, pkgs, starters, tests, union(p.TestImports, p.XTestImports))...)
	}
	return problems
}

func rootReach(modPath string, pkgs map[string]listedPackage, starters map[string]string, from sourceFile, roots []string) []string {
	if execPermitted(modPath, from) {
		return nil
	}
	who := from.Pkg
	if from.Test {
		who += " (tests)"
	}
	var problems []string
	for _, root := range roots {
		if why := reachesProcess(modPath, pkgs, starters, root, map[string]bool{}); why != "" {
			problems = append(problems, fmt.Sprintf("%s reaches a process start through %s: %s (AGENTS.md invariant 1)", who, root, why))
		}
	}
	return problems
}

// reachesProcess returns why imp, or a package it imports, can start a
// program, or "" when nothing on the way can.
func reachesProcess(modPath string, pkgs map[string]listedPackage, starters map[string]string, imp string, seen map[string]bool) string {
	switch {
	case imp == processStdlib:
		return "os/exec runs programs"
	case starters[imp] != "":
		return starters[imp]
	case seen[imp]:
		return ""
	case isMain(pkgs, imp):
		return toolingReason(modPath, imp)
	}
	seen[imp] = true
	for _, next := range pkgs[imp].Imports {
		if why := reachesProcess(modPath, pkgs, starters, next, seen); why != "" {
			return why
		}
	}
	return ""
}

// toolingReason reports a main-module package whose tree may run programs
// for anyone, so importing it hands that right on.
func toolingReason(modPath, imp string) string {
	for _, dir := range execAllowed {
		if underPath(imp, path.Join(modPath, dir)) {
			return dir + " may run programs and is never imported by the product"
		}
	}
	return ""
}
