package state

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Inside package state a MAC key has one origin. The rules are checked on
// type-checked objects, not names, so an alias, a method with the same
// name, a function value or a write through copy or an index cannot slip
// past:
//   - open is referenced only by OpenUser and OpenWithSecret, openDir only
//     by open and userSecret, newMACKey only by open, and OpenWithSecret by
//     no non-test code here;
//   - Store, Run and macKey values are built (literal, new or conversion)
//     only by openDir, Store.newRun and newMACKey;
//   - a macKey's bytes are only set in newMACKey and only read by len and
//     hmac.New; Store.key is written only by open and Run.key only by the
//     literal in Store.newRun.
var (
	keyCallers  = map[string][]string{"open": {"OpenUser", "OpenWithSecret"}, "openDir": {"open", "userSecret"}, "newMACKey": {"open"}, "OpenWithSecret": nil}
	keyBuilders = map[string]string{"Store": "openDir", "Run": "Store.newRun", "macKey": "newMACKey"}
)

// Acceptance (#160, tester L2 and L3).
func TestKeysComeOnlyFromOpen(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if ok, _ := build.Default.MatchFile(".", name); !ok || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(data)
	}
	problems, err := keyOriginProblems(files)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

const keyOriginBase = `package state

type macKey struct{ b []byte }
type Store struct{ key macKey }
type Run struct{ key macKey }

func newMACKey(s []byte) macKey { return macKey{b: s} }
func (k macKey) set() bool      { return len(k.b) == 32 }
func open(d string, s []byte) *Store { st := openDir(d); st.key = newMACKey(s); return st }
func openDir(string) *Store          { return &Store{} }
func (s *Store) newRun() *Run        { return &Run{key: s.key} }
func OpenUser(d string) *Store       { return open(d, userSecret()) }
func OpenWithSecret(d string, s []byte) *Store { return open(d, s) }
func userSecret() []byte             { _ = openDir(""); return nil }
`

// The checker catches each way a key could be forged or reached.
func TestKeyOriginCatchesBypasses(t *testing.T) {
	tests := []struct{ name, extra, want string }{
		{"base", "", ""},
		{"OpenWithSecret called here", `func extra() { OpenWithSecret("", nil) }`, "OpenWithSecret referenced in extra"},
		{"method named OpenUser", `type T struct{}; func (T) OpenUser() { open("", nil) }`, "open referenced in T.OpenUser"},
		{"method named newRun", `type T struct{}; func (T) newRun() *Run { return &Run{} }`, "Run built in T.newRun"},
		{"open as a value", `var f = open`, "open referenced in a package-level declaration"},
		{"open in a closure var", `var g = func() { open("", nil) }`, "open referenced in a package-level declaration"},
		{"newMACKey elsewhere", `func extra() { _ = newMACKey(nil) }`, "newMACKey referenced in extra"},
		{"openDir elsewhere", `func extra() { _ = openDir("") }`, "openDir referenced in extra"},
		{"copy into key", `func extra(s *Store) { copy(s.key.b, "x") }`, "macKey.b used in extra"},
		{"index write", `func extra(k macKey) { k.b[0] = 1 }`, "macKey.b used in extra"},
		{"slice escapes", `func extra(k macKey) []byte { return k.b }`, "macKey.b used in extra"},
		{"store key assigned", `func extra(s *Store, k macKey) { s.key = k }`, "Store.key written in extra"},
		{"store key address", `func extra(s *Store) *macKey { return &s.key }`, "Store.key written in extra"},
		{"run key assigned", `func extra(r *Run, s *Store) { r.key = s.key }`, "Run.key written in extra"},
		{"key literal", `func extra() macKey { return macKey{} }`, "macKey built in extra"},
		{"key conversion", `func extra() macKey { return macKey(struct{ b []byte }{}) }`, "macKey built in extra"},
		{"store literal", `func extra() *Store { return &Store{} }`, "Store built in extra"},
		{"new run", `func extra() *Run { return new(Run) }`, "Run built in extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems, err := keyOriginProblems(map[string]string{"base.go": keyOriginBase, "extra.go": "package state\n\n" + tt.extra + "\n"})
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(problems, "\n")
			if (tt.want == "") != (got == "") || !strings.Contains(got, tt.want) {
				t.Fatalf("problems = %q; want %q", got, tt.want)
			}
		})
	}
}

// sourceImporter is shared so the standard library is type-checked once.
var sourceImporter = sync.OnceValue(func() types.Importer {
	return importer.ForCompiler(token.NewFileSet(), "source", nil)
})

// keyOriginProblems type-checks files as package state and applies the
// rules above.
func keyOriginProblems(files map[string]string) ([]string, error) {
	fset := token.NewFileSet()
	var parsed []*ast.File
	for name, src := range files {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, f)
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}
	pkg, err := (&types.Config{Importer: sourceImporter()}).Check("state", fset, parsed, info)
	if err != nil {
		return nil, fmt.Errorf("type-check: %w", err)
	}
	c := keyChecker{fset: fset, info: info, scope: pkg.Scope()}
	for _, f := range parsed {
		for _, decl := range f.Decls {
			c.decl(decl)
		}
	}
	slices.Sort(c.problems)
	return c.problems, nil
}

type keyChecker struct {
	fset     *token.FileSet
	info     *types.Info
	scope    *types.Scope
	problems []string
}

func (c *keyChecker) decl(decl ast.Decl) {
	var in types.Object // the enclosing package-level function or method, if any
	if fd, ok := decl.(*ast.FuncDecl); ok {
		in = c.info.Defs[fd.Name]
	}
	ast.PreorderStack(decl, nil, func(n ast.Node, stack []ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			c.ident(x, stack, in)
		case *ast.CompositeLit:
			c.built(x, c.info.TypeOf(x), in)
		case *ast.CallExpr:
			c.call(x, in)
		}
		return true
	})
}

func (c *keyChecker) report(n ast.Node, in types.Object, format string, args ...any) {
	where := "a package-level declaration"
	if in != nil {
		where = funcName(in)
	}
	msg := fmt.Sprintf(format, args...) + " in " + where
	c.problems = append(c.problems, fmt.Sprintf("%s: %s", c.fset.Position(n.Pos()), msg))
}

// funcName names a function "f" and a method "T.m" (receiver pointer
// dropped), so a method never passes for the function of the same name.
func funcName(in types.Object) string {
	fn, ok := in.(*types.Func)
	if !ok || fn.Signature().Recv() == nil {
		return in.Name()
	}
	t := types.Unalias(fn.Signature().Recv().Type())
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		return named.Obj().Name() + "." + fn.Name()
	}
	return "?." + fn.Name()
}

// is reports whether in, the enclosing declaration, is one of names.
func (c *keyChecker) is(in types.Object, names ...string) bool {
	return in != nil && slices.Contains(names, funcName(in))
}

func (c *keyChecker) ident(id *ast.Ident, stack []ast.Node, in types.Object) {
	obj := c.info.Uses[id]
	if obj == nil {
		return
	}
	if callers, watched := keyCallers[obj.Name()]; watched && obj == c.scope.Lookup(obj.Name()) && !c.is(in, callers...) {
		c.report(id, in, "%s referenced", obj.Name())
		return
	}
	if v, ok := obj.(*types.Var); ok && v.IsField() {
		c.field(id, v, stack, in)
	}
}

// field applies the macKey.b, Store.key and Run.key rules.
func (c *keyChecker) field(id *ast.Ident, v *types.Var, stack []ast.Node, in types.Object) {
	owner := c.fieldOwner(v)
	if owner == "" {
		return
	}
	parent := stack[len(stack)-1]
	if kv, ok := parent.(*ast.KeyValueExpr); ok && kv.Key == id {
		if (owner == "macKey" && !c.is(in, "newMACKey")) || (owner == "Run" && !c.is(in, "Store.newRun")) || owner == "Store" {
			c.report(id, in, "%s.%s set", owner, v.Name())
		}
		return
	}
	var grand ast.Node
	if len(stack) >= 2 {
		grand = stack[len(stack)-2]
	}
	if owner == "macKey" {
		if !c.readByLenOrHMAC(parent, grand) {
			c.report(id, in, "macKey.b used")
		}
		return
	}
	if written(parent, grand) && (owner != "Store" || !c.is(in, "open")) {
		c.report(id, in, "%s.key written", owner)
	}
}

// fieldOwner names the watched struct v belongs to, or "".
func (c *keyChecker) fieldOwner(v *types.Var) string {
	for owner, field := range map[string]string{"macKey": "b", "Store": "key", "Run": "key"} {
		tn, ok := c.scope.Lookup(owner).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := tn.Type().Underlying().(*types.Struct)
		for i := 0; ok && i < st.NumFields(); i++ {
			if st.Field(i) == v && v.Name() == field {
				return owner
			}
		}
	}
	return ""
}

// readByLenOrHMAC accepts k.b only as a direct argument of len or hmac.New.
func (c *keyChecker) readByLenOrHMAC(parent, grand ast.Node) bool {
	sel, ok := parent.(*ast.SelectorExpr)
	call, isCall := grand.(*ast.CallExpr)
	if !ok || !isCall || !slices.Contains(call.Args, ast.Expr(sel)) {
		return false
	}
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		b, ok := c.info.Uses[fn].(*types.Builtin)
		return ok && b.Name() == "len"
	case *ast.SelectorExpr:
		f, ok := c.info.Uses[fn.Sel].(*types.Func)
		return ok && f.Pkg() != nil && f.Pkg().Path() == "crypto/hmac" && f.Name() == "New"
	}
	return false
}

// written reports a selector x.key that is assigned or has its address taken.
func written(parent, grand ast.Node) bool {
	sel, ok := parent.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch g := grand.(type) {
	case *ast.AssignStmt:
		return slices.Contains(g.Lhs, ast.Expr(sel))
	case *ast.UnaryExpr:
		return g.Op == token.AND
	}
	return false
}

// call applies the builder rule to new(T) and conversions T(x).
func (c *keyChecker) call(call *ast.CallExpr, in types.Object) {
	if id, ok := call.Fun.(*ast.Ident); ok && len(call.Args) == 1 {
		if b, ok := c.info.Uses[id].(*types.Builtin); ok && b.Name() == "new" {
			c.built(call, c.info.TypeOf(call.Args[0]), in)
			return
		}
	}
	if tv, ok := c.info.Types[call.Fun]; ok && tv.IsType() {
		c.built(call, tv.Type, in)
	}
}

// built reports a value of a watched type made outside its constructor.
func (c *keyChecker) built(n ast.Node, t types.Type, in types.Object) {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Parent() != c.scope {
		return
	}
	if builder, watched := keyBuilders[named.Obj().Name()]; watched && !c.is(in, builder) {
		c.report(n, in, "%s built", named.Obj().Name())
	}
}
