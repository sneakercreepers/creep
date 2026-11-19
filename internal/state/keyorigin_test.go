package state

import (
	"fmt"
	"go/ast"
	"slices"
)

// Inside package state a MAC key comes from one place: open, called only
// by OpenUser and OpenWithSecret, builds it with newMACKey; Store, Run and
// macKey values are built only by their constructors, and no other code
// assigns a store's key or a key's bytes. So sign and verify can only ever
// use a key one of the two entry points was given (or the zero key, which
// signs and verifies nothing).
var (
	keyCallers = map[string][]string{
		"open":      {"OpenUser", "OpenWithSecret"},
		"openDir":   {"open", "userSecret"},
		"newMACKey": {"open"},
	}
	keyLiterals = map[string]string{"Store": "openDir", "Run": "newRun", "macKey": "newMACKey"}
	keyFields   = map[string]string{"key": "open", "b": ""} // "" means nowhere
)

// structuralProblems checks one non-test file of package state against the
// rules above.
func structuralProblems(f *ast.File) []problem {
	var problems []problem
	for _, decl := range f.Decls {
		fn := ""
		if d, ok := decl.(*ast.FuncDecl); ok {
			fn = d.Name.Name
		}
		problems = append(problems, declProblems(decl, fn)...)
	}
	return problems
}

func declProblems(decl ast.Decl, fn string) []problem {
	calls := map[*ast.Ident]bool{}
	ast.Inspect(decl, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok {
				calls[id] = true
			}
		}
		return true
	})
	var self *ast.Ident // the declared name, not a use
	if d, ok := decl.(*ast.FuncDecl); ok {
		self = d.Name
	}
	var problems []problem
	report := func(n ast.Node, format string, args ...any) {
		problems = append(problems, problem{n.Pos(), fmt.Sprintf(format, args...)})
	}
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			ast.Inspect(x.X, visit) // x.Sel is a field or method name
			return false
		case *ast.Ident:
			if x != self {
				identProblem(x, fn, calls, report)
			}
		case *ast.CompositeLit:
			literalProblem(x.Type, fn, report)
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
				literalProblem(x.Args[0], fn, report)
			}
		case *ast.AssignStmt:
			assignProblems(x, fn, report)
		}
		return true
	}
	ast.Inspect(decl, visit)
	return problems
}

func identProblem(id *ast.Ident, fn string, calls map[*ast.Ident]bool, report func(ast.Node, string, ...any)) {
	allowed, watched := keyCallers[id.Name]
	if !watched || (calls[id] && slices.Contains(allowed, fn)) {
		return
	}
	if fn == "" {
		report(id, "%s used outside a function", id.Name)
		return
	}
	report(id, "%s used in %s", id.Name, fn)
}

func literalProblem(typ ast.Expr, fn string, report func(ast.Node, string, ...any)) {
	id, ok := typ.(*ast.Ident)
	if !ok {
		return
	}
	if want, watched := keyLiterals[id.Name]; watched && fn != want {
		report(id, "%s literal in %s", id.Name, fnName(fn))
	}
}

func assignProblems(a *ast.AssignStmt, fn string, report func(ast.Node, string, ...any)) {
	for _, lhs := range a.Lhs {
		sel, ok := lhs.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if want, watched := keyFields[sel.Sel.Name]; watched && (want == "" || fn != want) {
			report(sel, "%s assigned in %s", sel.Sel.Name, fnName(fn))
		}
	}
}

func fnName(fn string) string {
	if fn == "" {
		return "a package-level declaration"
	}
	return fn
}
