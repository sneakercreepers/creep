package main

import (
	"strings"
	"testing"
)

// sdkPkgPath is the MCP SDK package internal/mcp imports (ADR 0027).
const sdkPkgPath = "github.com/modelcontextprotocol/go-sdk/mcp"

// The link proof covers only the package ADR 0027 names: any other main
// package importing the SDK still fails the import-graph net check, and a
// module that only looks like the SDK gets no exemption.
func TestLinkExemptOnlyForMCP(t *testing.T) {
	sdkPkg := func(mod string) listedPackage {
		p := listedPackage{ImportPath: sdkPkgPath, Imports: []string{"net"}}
		p.Module = &struct {
			Path string
			Main bool
		}{mod, false}
		return p
	}
	pkgs := graph([]string{"internal/mcp", "internal/cli"}, "internal/mcp>"+sdkPkgPath, "internal/cli>"+sdkPkgPath, "internal/mcp[test]>"+sdkPkgPath)
	pkgs[sdkPkgPath] = sdkPkg("github.com/modelcontextprotocol/go-sdk")
	pkgs["net"] = listedPackage{ImportPath: "net", Standard: true}
	got := checkNetReach(testMod, pkgs)
	if len(got) != 1 || !strings.Contains(got[0], "internal/cli reaches package net") {
		t.Errorf("got %v, want only internal/cli flagged", got)
	}
	pkgs[sdkPkgPath] = sdkPkg("example.com/look-alike")
	if got := checkNetReach(testMod, pkgs); len(got) != 3 {
		t.Errorf("a look-alike module was exempted: %v", got)
	}
}

// The same exemption holds for the process reach check, and only there.
func TestProcessReachExemptOnlyForMCP(t *testing.T) {
	pkgs := graph([]string{"internal/mcp", "internal/cli"}, "internal/mcp>"+sdkPkgPath, "internal/cli>"+sdkPkgPath)
	p := pkgs[sdkPkgPath]
	p.Imports = []string{"os/exec"}
	p.Module = &struct {
		Path string
		Main bool
	}{"github.com/modelcontextprotocol/go-sdk", false}
	pkgs[sdkPkgPath] = p
	got := checkProcessReach(testMod, pkgs, map[string]string{})
	if len(got) != 1 || !strings.Contains(got[0], "internal/cli reaches a process start") {
		t.Errorf("got %v, want only internal/cli flagged", got)
	}
}
