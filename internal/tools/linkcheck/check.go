package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// checkLinkReach walks the linker graph from every symbol of third-party
// code and reports each watched function it reaches, with the path. The
// walk stops at main-module symbols, which the import rules check, and at
// a reviewed edge, which it records in seen. It does not enter funcdata
// the linker deduplicates by content, and it judges type descriptors,
// itabs and static data only by what they lead to, never by their name.
func checkLinkReach(modPath string, g linkGraph, seen map[string]bool) []string {
	parent, queue := thirdPartySeeds(modPath, g)
	problems := linkedPrimitives(queue)
	for len(queue) > 0 {
		sym := queue[0]
		queue = queue[1:]
		for _, next := range g[sym] {
			if _, done := parent[next]; done || isAux(next) || isMainSymbol(modPath, next) {
				continue
			}
			// A reviewed edge is not followed, but next stays unvisited: any
			// other edge into it is still checked.
			if edge := sym + " -> " + next; linkReviewed[edge] != "" {
				seen[edge] = true
				continue
			}
			parent[next] = sym
			switch {
			case isWatched(next):
				problems = append(problems, fmt.Sprintf("third-party code links %s: %s (AGENTS.md invariant 1, ADR 0027)", next, linkPath(parent, next)))
			case isRawSysEdge(modPath, sym, next):
				problems = append(problems, fmt.Sprintf("third-party code makes a raw system call %s: %s (AGENTS.md invariant 1, ADR 0027)", next, linkPath(parent, next)))
			default:
				queue = append(queue, next)
			}
		}
	}
	return problems
}

// thirdPartySeeds start the walk: every third-party symbol but
// deduplicated funcdata.
func thirdPartySeeds(modPath string, g linkGraph) (map[string]string, []string) {
	parent := map[string]string{}
	var queue []string
	for _, sym := range sortedSymbols(g) {
		if isThirdParty(modPath, symbolPackage(sym)) && !isAux(sym) {
			parent[sym] = ""
			queue = append(queue, sym)
		}
	}
	return parent, queue
}

// linkedPrimitives reports the x/sys socket and exec wrappers among the
// seeds: x/sys is third-party, so its wrappers are seeds, and an edge
// into a seed is never followed. Being linked at all means some code
// calls one.
func linkedPrimitives(seeds []string) []string {
	var problems []string
	for _, sym := range seeds {
		if isWatched(sym) {
			problems = append(problems, fmt.Sprintf("third-party code links %s (AGENTS.md invariant 1, ADR 0027)", sym))
		}
	}
	return problems
}

// staleReviewed reports linkReviewed entries no release binary links.
func staleReviewed(seen map[string]bool) []string {
	var problems []string
	for edge := range linkReviewed {
		if !seen[edge] {
			problems = append(problems, fmt.Sprintf("linkReviewed lists %q, which no release binary links any more; remove it", edge))
		}
	}
	sort.Strings(problems)
	return problems
}

// linkPath is the chain of symbols from a third-party seed to sym.
func linkPath(parent map[string]string, sym string) string {
	chain := []string{sym}
	for p := parent[sym]; p != ""; p = parent[p] {
		chain = append(chain, p)
	}
	slices.Reverse(chain)
	return strings.Join(chain, " -> ")
}

func sortedSymbols(g linkGraph) []string {
	syms := make([]string, 0, len(g))
	for s := range g {
		syms = append(syms, s)
	}
	sort.Strings(syms)
	return syms
}

// isWatched reports a function that opens connections or starts a
// program. Type descriptors, itabs and static data are never watched by
// name: a deduplicated one can carry another package's name.
func isWatched(sym string) bool {
	if strings.HasPrefix(sym, "type:") || strings.HasPrefix(sym, "go:") || strings.Contains(sym, ".stmp_") {
		return false
	}
	if slices.Contains(watchedSymbols, sym) || isSysPrimitive(sym) {
		return true
	}
	pkg := symbolPackage(sym)
	return slices.ContainsFunc(watchedPackages, func(w string) bool { return pkg == w || strings.HasPrefix(pkg, w+"/internal/") })
}

func isAux(sym string) bool {
	return strings.HasPrefix(sym, "gclocals") || slices.ContainsFunc(auxSuffixes, func(s string) bool { return strings.HasSuffix(sym, s) })
}

func isMainSymbol(modPath, sym string) bool {
	return underPath(symbolPackage(sym), modPath)
}

// isThirdParty reports a package outside the standard library (whose
// first path element has no dot) and the main module.
func isThirdParty(modPath, pkg string) bool {
	first, _, _ := strings.Cut(pkg, "/")
	return strings.Contains(first, ".") && !underPath(pkg, modPath)
}

// symbolPackage is the import path of a linker symbol: "net/http" for
// "net/http.(*Client).Do" and "type:*net/http.Client", "" for one with no
// package, such as "go:string.x". A generic's type arguments, which can
// hold other paths, are cut first.
func symbolPackage(sym string) string {
	sym = strings.TrimPrefix(strings.TrimPrefix(sym, "type:"), "*")
	if strings.HasPrefix(sym, "go:") {
		return ""
	}
	if i := strings.IndexByte(sym, '['); i >= 0 {
		sym = sym[:i]
	}
	slash := strings.LastIndexByte(sym, '/')
	dot := strings.IndexByte(sym[slash+1:], '.')
	if dot < 0 {
		return ""
	}
	return sym[:slash+1+dot]
}
