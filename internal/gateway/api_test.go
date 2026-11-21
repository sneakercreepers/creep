package gateway

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const gatewayPath = "github.com/sneakercreepers/creep/internal/gateway"

// leakTypes let their holder send bytes without EgressLog.Send, so without
// consent or egress.log, or choose where a dial goes (#115).
var leakTypes = map[string]bool{
	"net/http.Client":       true,
	"net/http.Transport":    true,
	"net/http.RoundTripper": true,
	"net.Conn":              true,
	"net.Dialer":            true,
}

// No exported object of the gateway reaches a raw HTTP client, transport,
// round tripper, connection or dialer, through any type a caller can name
// or receive: function and method signatures, variables, aliases, exported
// and embedded fields, interface methods and type arguments. A gateway
// function or method may not return any either, which would hide one.
func TestNoTransportSeamExported(t *testing.T) {
	imp := exportImporter(t)
	pkg, err := imp.Import(gatewayPath)
	if err != nil {
		t.Fatalf("type-check the gateway: %v", err)
	}
	for _, p := range exportedLeaks(pkg) {
		t.Errorf("%s; send only through EgressLog.Send", p)
	}
}

// The guard catches every shape a leak can take, not only a named result.
func TestLeakGuardCatchesEveryShape(t *testing.T) {
	tests := []struct {
		name, src string
		leaks     bool
	}{
		{"alias", `type HC = http.Client`, true},
		{"alias chain", `type A = http.Transport; type B = A`, true},
		{"embedded field", `type W struct{ *http.Client }`, true},
		{"exported field", `type W struct{ RT http.RoundTripper }`, true},
		{"exported var", `var Default = &http.Client{}`, true},
		{"func var", `var Dial = net.Dial`, true},
		{"any result", `func Raw() any { return nil }`, true},
		{"empty interface result", `func Raw() (interface{}, error) { return nil, nil }`, true},
		{"interface method", `type Opener interface{ Open() net.Conn }`, true},
		{"embedded interface", `type Opener interface{ http.RoundTripper }`, true},
		{"method result", `type T struct{}; func (T) RT() http.RoundTripper { return nil }`, true},
		{"parameter", `func Use(d *net.Dialer) {}`, true},
		{"callback parameter", `func Use(f func() net.Conn) {}`, true},
		{"unexported type returned", `type inner struct{ C *http.Client }; func New() *inner { return nil }`, true},
		{"generic instantiation", `type Box[T any] struct{ V T }; func Get() Box[*http.Transport] { return Box[*http.Transport]{} }`, true},
		{"generic constraint", `type Tr interface{ *http.Transport }; func Get[T Tr]() {}`, true},
		{"map and slice", `var M map[string][]*http.Client`, true},
		{"channel", `func C() <-chan net.Conn { return nil }`, true},
		{"unexported field", `type T struct{ c *http.Client }; func (T) Close() {}`, false},
		{"unexported func", `func raw() *http.Client { return nil }; func Name() string { return "" }`, false},
		{"header map", `type Call struct{ Header http.Header }`, false},
	}
	imp := exportImporter(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exportedLeaks(checkFixture(t, imp, tt.src))
			if leaks := len(got) > 0; leaks != tt.leaks {
				t.Fatalf("leaks = %v %q, want %v", leaks, got, tt.leaks)
			}
		})
	}
}

// exportImporter reads the compiler's export data for the gateway and its
// dependencies, as the build for this platform made it, so the guard checks
// the real package without type-checking the standard library from source.
func exportImporter(t *testing.T) types.Importer {
	t.Helper()
	out, err := exec.Command("go", "list", "-export", "-deps", "-f", "{{.ImportPath}}\t{{.Export}}", gatewayPath).Output()
	if err != nil {
		t.Fatalf("go list -export: %v", err)
	}
	exports := map[string]string{}
	for line := range strings.Lines(string(out)) {
		path, file, _ := strings.Cut(strings.TrimSpace(line), "\t")
		exports[path] = file
	}
	return importer.ForCompiler(token.NewFileSet(), "gc", func(path string) (io.ReadCloser, error) {
		if exports[path] == "" {
			return nil, fmt.Errorf("no export data for %q", path)
		}
		return os.Open(exports[path])
	})
}

func checkFixture(t *testing.T, imp types.Importer, decls string) *types.Package {
	t.Helper()
	fset := token.NewFileSet()
	src := "package p\n\nimport (\n\t\"net\"\n\t\"net/http\"\n)\n\nvar _ net.Conn\nvar _ http.Header\n\n" + decls + "\n"
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := (&types.Config{Importer: imp}).Check("example.com/p", fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

// leakWalker visits every type reachable from a package's exported API.
type leakWalker struct {
	pkg      *types.Package
	seen     map[types.Type]bool
	problems []string
}

func exportedLeaks(pkg *types.Package) []string {
	w := &leakWalker{pkg: pkg, seen: map[types.Type]bool{}}
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if !obj.Exported() {
			continue
		}
		switch o := obj.(type) {
		case *types.Func:
			w.signature(name, o.Signature(), true)
		case *types.Var, *types.TypeName:
			w.walk(name, o.Type())
		}
	}
	return w.problems
}

func (w *leakWalker) walk(where string, t types.Type) {
	t = types.Unalias(t)
	if n, ok := t.(*types.Named); ok && n.Obj().Pkg() != nil {
		if name := n.Obj().Pkg().Path() + "." + n.Obj().Name(); leakTypes[name] {
			w.problems = append(w.problems, where+" exposes "+name)
			return
		}
	}
	if w.seen[t] {
		return
	}
	w.seen[t] = true
	switch t := t.(type) {
	case *types.Named:
		w.named(where, t)
	case *types.Pointer:
		w.walk(where, t.Elem())
	case *types.Slice:
		w.walk(where, t.Elem())
	case *types.Array:
		w.walk(where, t.Elem())
	case *types.Chan:
		w.walk(where, t.Elem())
	case *types.Map:
		w.walk(where, t.Key())
		w.walk(where, t.Elem())
	case *types.Signature:
		w.signature(where, t, false)
	case *types.Struct:
		w.fields(where, t)
	case *types.Interface:
		w.iface(where, t)
	case *types.TypeParam:
		w.walk(where, t.Constraint())
	case *types.Union:
		for i := range t.Len() {
			w.walk(where, t.Term(i).Type())
		}
	}
}

func (w *leakWalker) named(where string, n *types.Named) {
	own := n.Obj().Pkg() == w.pkg
	for i := range n.TypeArgs().Len() {
		w.walk(where, n.TypeArgs().At(i))
	}
	for i := range n.TypeParams().Len() {
		w.walk(where, n.TypeParams().At(i).Constraint())
	}
	w.walk(where, n.Underlying())
	for i := range n.NumMethods() {
		if m := n.Method(i); m.Exported() {
			w.signature(where+"."+m.Name(), m.Signature(), own)
		}
	}
}

// signature walks parameters and results; own marks a gateway signature,
// whose results may not be any.
func (w *leakWalker) signature(where string, s *types.Signature, own bool) {
	for i := range s.TypeParams().Len() {
		w.walk(where, s.TypeParams().At(i).Constraint())
	}
	for v := range s.Params().Variables() {
		w.walk(where, v.Type())
	}
	for v := range s.Results().Variables() {
		if own && isEmptyInterface(v.Type()) {
			w.problems = append(w.problems, where+" returns any, which can hide a client")
		}
		w.walk(where, v.Type())
	}
}

func (w *leakWalker) fields(where string, s *types.Struct) {
	for f := range s.Fields() {
		if f.Exported() || f.Embedded() {
			w.walk(where+"."+f.Name(), f.Type())
		}
	}
}

func (w *leakWalker) iface(where string, it *types.Interface) {
	for i := range it.NumEmbeddeds() {
		w.walk(where, it.EmbeddedType(i))
	}
	for i := range it.NumMethods() {
		if m := it.Method(i); m.Exported() {
			w.signature(where+"."+m.Name(), m.Signature(), m.Pkg() == w.pkg)
		}
	}
}

func isEmptyInterface(t types.Type) bool {
	it, ok := types.Unalias(t).(*types.Interface)
	return ok && it.Empty()
}
