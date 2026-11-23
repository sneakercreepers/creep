package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// sdkModule is the MCP SDK (ADR 0027), the one module internal/tools/budget
// lets reach package net at the import level because this tool checks it.
const sdkModule = "github.com/modelcontextprotocol/go-sdk"

// sdkAllowed lists, per SDK package, the only names creep's code and tests
// may use: the server, typed tools and the io.Reader/io.Writer transport,
// and for tests the client. The HTTP, SSE, command and in-memory
// transports, OAuth and every other SDK package stay unused, so they are
// never linked and no test opens a socket or starts a program through
// them.
var sdkAllowed = map[string][]string{
	sdkModule + "/mcp": {
		"AddTool", "CallToolParams", "CallToolRequest", "CallToolResult", "ClientSession",
		"IOTransport", "Implementation", "NewClient", "NewServer", "Server", "ServerOptions", "TextContent",
		"Tool", "ToolAnnotations",
	},
}

// checkSourceUses parses every .go file of the module, tests included, and
// reports each SDK name sdkAllowed does not list.
func checkSourceUses(root string) ([]string, error) {
	var problems []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return skipDir(path, root, d.Name())
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.SkipObjectResolution)
		if err != nil || !importsSDK(file) {
			return err
		}
		if file, err = parser.ParseFile(fset, path, nil, parser.SkipObjectResolution); err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		problems = append(problems, checkUses(filepath.ToSlash(rel), sdkUses(file))...)
		return nil
	})
	return problems, err
}

// skipDir skips what the go command never builds: testdata, vendor and
// directories starting with "." or "_" (agent worktrees, .git).
func skipDir(path, root, name string) error {
	if path != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
		return filepath.SkipDir
	}
	return nil
}

func importsSDK(file *ast.File) bool {
	return slices.ContainsFunc(file.Imports, func(spec *ast.ImportSpec) bool {
		imp, err := strconv.Unquote(spec.Path.Value)
		return err == nil && underPath(imp, sdkModule)
	})
}

// sdkUses returns each name file uses from an SDK package, as
// "<import path>.<name>". A dot or blank import is "<import path>.*",
// which no allowlist holds.
func sdkUses(file *ast.File) []string {
	local := map[string]string{}
	var uses []string
	for _, spec := range file.Imports {
		imp, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !underPath(imp, sdkModule) {
			continue
		}
		name := imp[strings.LastIndexByte(imp, '/')+1:]
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." || name == "_" {
			uses = append(uses, imp+".*")
		}
		local[name] = imp
	}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && local[id.Name] != "" {
			uses = append(uses, local[id.Name]+"."+sel.Sel.Name)
		}
		return true
	})
	return uses
}

func checkUses(name string, uses []string) []string {
	var problems []string
	for _, use := range uses {
		dot := strings.LastIndexByte(use, '.')
		if !slices.Contains(sdkAllowed[use[:dot]], use[dot+1:]) {
			problems = append(problems, fmt.Sprintf("%s uses %s, which sdkAllowed does not list: only the stdio server and its test client may be used (ADR 0027)", name, use))
		}
	}
	return problems
}

func underPath(pkg, root string) bool {
	return pkg == root || strings.HasPrefix(pkg, root+"/")
}
