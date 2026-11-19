package state

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const statePkg = "github.com/sneakercreepers/creep/internal/state"

// The public test key signs committed fixtures (testdata/v1, the reader's
// replay fixtures), so a store opened with it would trust anything a
// repository plants. Production code must never reach it: every non-test
// Open in the module takes a secret straight from UserSecret (UserSecret
// opens the key store itself with a zero key, which signs nothing), and no
// non-test file holds the key in any encoding. _test.go files never build
// into the binary, so the key cannot ship.
func TestOnlyUserSecretOpensStores(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	files := moduleSources(t, root)
	if _, ok := files["internal/state/mac.go"]; !ok || len(files) < 50 {
		t.Fatalf("walk of %s found %d files without internal/state/mac.go", root, len(files))
	}
	for name, src := range files {
		for _, p := range secretProblems(name, src) {
			t.Error(p)
		}
	}
}

// The checker itself catches each way the test key could reach Open.
func TestSecretProblemsCatchesBypasses(t *testing.T) {
	head := "package cli\n\nimport (\n\t\"bytes\"\n\t\"github.com/sneakercreepers/creep/internal/state\"\n)\n\n"
	tests := []struct {
		name, file, src string
		want            string
	}{
		{"user secret", "internal/cli/a.go", head + "func f(d string) { s, _ := state.UserSecret(); state.Open(d, s) }", ""},
		{"user secret in a closure", "internal/cli/a.go", head + "func f(d string) { s, _ := state.UserSecret(); _ = func() { state.Open(d, s) } }", ""},
		{"fixed key", "internal/cli/a.go", head + "func f(d string) { state.Open(d, bytes.Repeat([]byte{0x5a}, 32)) }", "not from UserSecret"},
		{"parameter", "internal/cli/a.go", head + "func f(d string, k []byte) { state.Open(d, k) }", "not from UserSecret"},
		{"reassigned", "internal/cli/a.go", head + "func f(d string, k []byte) { s, _ := state.UserSecret(); s = k; state.Open(d, s) }", "not from UserSecret"},
		{"other source", "internal/cli/a.go", head + "func g() ([]byte, error) { return nil, nil }\nfunc f(d string) { s, _ := g(); state.Open(d, s) }", "not from UserSecret"},
		{"open as a value", "internal/cli/a.go", head + "var open = state.Open", "used as a value"},
		{"alias", "internal/cli/a.go", "package cli\n\nimport st \"github.com/sneakercreepers/creep/internal/state\"\n\nfunc f(d string, k []byte) { st.Open(d, k) }", "not from UserSecret"},
		{"dot import", "internal/cli/a.go", "package cli\n\nimport . \"github.com/sneakercreepers/creep/internal/state\"\n\nvar _ = SecretBytes", "dot import"},
		{"hex key", "internal/cli/a.go", "package cli\n\nconst k = \"" + hex.EncodeToString(testSecret) + "\"", "public test key"},
		{"base64 key", "internal/cli/a.go", "package cli\n\nconst k = \"" + base64.StdEncoding.EncodeToString(testSecret) + "\"", "public test key"},
		{"zero key in UserSecret", "internal/state/a.go", "package state\n\nfunc UserSecret() { Open(\"d\", make([]byte, SecretBytes)) }", ""},
		{"zero key elsewhere", "internal/state/a.go", "package state\n\nfunc Other() { Open(\"d\", make([]byte, SecretBytes)) }", "not from UserSecret"},
		{"inside state", "internal/state/a.go", "package state\n\nfunc f(k []byte) { s, _ := UserSecret(); Open(\"d\", s); Open(\"d\", k) }", "not from UserSecret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(secretProblems(tt.file, tt.src), "\n")
			if (tt.want == "") != (got == "") || !strings.Contains(got, tt.want) {
				t.Fatalf("problems = %q; want %q", got, tt.want)
			}
		})
	}
}

// moduleSources returns every non-test .go file of the module at root by
// slash path, skipping hidden directories, testdata and nested modules
// (agent worktrees).
func moduleSources(t *testing.T, root string) map[string]string {
	t.Helper()
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	fsys := r.FS()
	files := map[string]string{}
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return skipDir(fsys, p)
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		files[p] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func skipDir(fsys fs.FS, p string) error {
	if p == "." {
		return nil
	}
	if name := path.Base(p); strings.HasPrefix(name, ".") || name == "testdata" {
		return fs.SkipDir
	}
	if _, err := fs.Stat(fsys, path.Join(p, "go.mod")); err == nil {
		return fs.SkipDir
	}
	return nil
}

// secretProblems reports how the non-test file name could open a store with
// anything but UserSecret's result.
func secretProblems(name, src string) []string {
	var problems []string
	if keyEncoded(src) {
		problems = append(problems, name+": holds the public test key")
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return append(problems, fmt.Sprintf("%s: %v", name, err))
	}
	pkg, ok := stateName(f, strings.HasPrefix(name, "internal/state/"))
	if !ok {
		return append(problems, name+": dot import of internal/state hides Open from this check")
	}
	if pkg == "" {
		return problems
	}
	for _, decl := range f.Decls {
		for _, p := range openProblems(decl, pkg) {
			problems = append(problems, fmt.Sprintf("%s:%d: %s", name, fset.Position(p.pos).Line, p.why))
		}
	}
	return problems
}

func keyEncoded(src string) bool {
	h := hex.EncodeToString(testSecret)
	for _, enc := range []string{h, strings.ToUpper(h), base64.StdEncoding.EncodeToString(testSecret), base64.RawURLEncoding.EncodeToString(testSecret)} {
		if strings.Contains(src, enc) {
			return true
		}
	}
	return false
}

// stateName is how f names package state: "." inside it, its import name
// elsewhere, "" when f does not import it, and !ok for a dot import.
func stateName(f *ast.File, inState bool) (string, bool) {
	if inState && f.Name.Name == "state" {
		return ".", true
	}
	for _, spec := range f.Imports {
		if p, _ := strconv.Unquote(spec.Path.Value); p != statePkg {
			continue
		}
		if spec.Name == nil {
			return "state", true
		}
		return spec.Name.Name, spec.Name.Name != "."
	}
	return "", true
}

type problem struct {
	pos token.Pos
	why string
}

// openProblems checks one declaration: each Open call's secret must be a
// variable every assignment of which is a UserSecret call, and Open is never
// taken as a value.
func openProblems(decl ast.Decl, pkg string) []problem {
	fromUser := userSecretVars(decl, pkg)
	calls := map[ast.Expr]bool{} // Open references that are calls, or Open's own declaration
	if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
		calls[fn.Name] = true
	}
	var problems []problem
	ast.Inspect(decl, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !refersTo(call.Fun, pkg, "Open") {
			return true
		}
		calls[call.Fun] = true
		if len(call.Args) != 2 || !trustedSecret(call.Args[1], decl, fromUser) {
			problems = append(problems, problem{call.Pos(), "Open with a secret not from UserSecret"})
		}
		return true
	})
	var values func(n ast.Node) bool
	values = func(n ast.Node) bool {
		e, ok := n.(ast.Expr)
		if ok && refersTo(e, pkg, "Open") && !calls[e] {
			problems = append(problems, problem{e.Pos(), "Open used as a value"})
			return false
		}
		if sel, ok := n.(*ast.SelectorExpr); ok {
			ast.Inspect(sel.X, values) // sel.Sel is a field or method name, never package state's Open
			return false
		}
		return true
	}
	ast.Inspect(decl, values)
	return problems
}

// trustedSecret accepts a variable bound only to UserSecret's result, and
// UserSecret's own zero key for the key store.
func trustedSecret(arg ast.Expr, decl ast.Decl, fromUser map[string]bool) bool {
	if id, ok := arg.(*ast.Ident); ok {
		return fromUser[id.Name]
	}
	fn, ok := decl.(*ast.FuncDecl)
	call, isCall := arg.(*ast.CallExpr)
	return ok && fn.Recv == nil && fn.Name.Name == "UserSecret" && isCall && refersTo(call.Fun, "", "make")
}

// userSecretVars returns the variables of decl that are only ever assigned
// the first result of a UserSecret call.
func userSecretVars(decl ast.Decl, pkg string) map[string]bool {
	trusted := map[string]bool{}
	ast.Inspect(decl, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range a.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name == "_" {
				continue
			}
			fromUser := i == 0 && len(a.Rhs) == 1 && isUserSecretCall(a.Rhs[0], pkg)
			prev, seen := trusted[id.Name]
			trusted[id.Name] = fromUser && (!seen || prev)
		}
		return true
	})
	return trusted
}

func isUserSecretCall(e ast.Expr, pkg string) bool {
	call, ok := e.(*ast.CallExpr)
	return ok && refersTo(call.Fun, pkg, "UserSecret")
}

// refersTo reports whether e names pkg.name, or the bare name when pkg is
// "." (inside package state) or "" (a builtin).
func refersTo(e ast.Expr, pkg, name string) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return (pkg == "." || pkg == "") && x.Name == name
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		return ok && pkg != "." && pkg != "" && id.Name == pkg && x.Sel.Name == name
	}
	return false
}
