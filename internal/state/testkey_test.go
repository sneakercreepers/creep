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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const statePkg = "github.com/sneakercreepers/creep/internal/state"

// The public test key signs committed fixtures (testdata/v1, the reader's
// replay fixtures), so a store opened with it would trust anything a
// repository plants. It cannot reach production: outside this package,
// non-test code can only call OpenUser, which takes the key from the user's
// state.key (OpenWithSecret, Store and Run literals, and dot imports are
// refused here); inside it, keys come only from open (structuralProblems);
// and no non-test file holds the key in any common encoding. _test.go files
// never build into the binary.
func TestProductionUsesOnlyOpenUser(t *testing.T) {
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

// The checker catches each way a fixed key could reach a store.
func TestSecretProblemsCatchesBypasses(t *testing.T) {
	cli := func(body string) string {
		return "package cli\n\nimport \"github.com/sneakercreepers/creep/internal/state\"\n\n" + body
	}
	st := func(body string) string { return "package state\n\n" + body }
	z := strings.Repeat("Z", SecretBytes)
	tests := []struct {
		name, file, src, want string
	}{
		{"OpenUser", "internal/cli/a.go", cli("func f(d string) { state.OpenUser(d) }"), ""},
		{"OpenWithSecret call", "internal/cli/a.go", cli("func f(d string, k []byte) { state.OpenWithSecret(d, k) }"), "OpenWithSecret"},
		{"OpenWithSecret value", "internal/cli/a.go", cli("var open = state.OpenWithSecret"), "OpenWithSecret"},
		{"alias", "internal/cli/a.go", "package cli\n\nimport s \"github.com/sneakercreepers/creep/internal/state\"\n\nvar _ = s.OpenWithSecret", "OpenWithSecret"},
		{"dot import", "internal/cli/a.go", "package cli\n\nimport . \"github.com/sneakercreepers/creep/internal/state\"\n\nvar _ = SecretBytes", "dot import"},
		{"Store literal", "internal/cli/a.go", cli("var _ = &state.Store{}"), "literal"},
		{"new Run", "internal/cli/a.go", cli("var _ = new(state.Run)"), "literal"},
		{"raw key", "internal/cli/a.go", "package cli\n\nconst k = \"" + z + "\"", "public test key"},
		{"hex key", "internal/cli/a.go", "package cli\n\nconst k = \"" + strings.ToUpper(hex.EncodeToString(testSecret)) + "\"", "public test key"},
		{"base64 key", "internal/cli/a.go", "package cli\n\nconst k = \"" + base64.RawURLEncoding.EncodeToString(testSecret) + "\"", "public test key"},
		{"escaped key", "internal/cli/a.go", "package cli\n\nconst k = \"" + strings.Repeat(`\x5A`, SecretBytes) + "\"", "public test key"},
		{"byte list", "internal/cli/a.go", "package cli\n\nvar k = []byte{" + strings.Repeat("0x5a, ", SecretBytes) + "}", "public test key"},
		{"decimal list", "internal/cli/a.go", "package cli\n\nvar k = []byte{" + strings.Repeat("90,", SecretBytes) + "}", "public test key"},
		{"repeat", "internal/cli/a.go", "package cli\n\nimport \"bytes\"\n\nvar k = bytes.Repeat([]byte{'Z'}, 32)", "public test key"},
		{"repeat string", "internal/cli/a.go", "package cli\n\nimport \"strings\"\n\nvar k = strings.Repeat( \"Z\", 32)", "public test key"},
		{"open from OpenUser", "internal/state/a.go", st("func OpenUser(d string) { open(d, nil) }"), ""},
		{"open elsewhere", "internal/state/a.go", st("func Other(d string) { open(d, nil) }"), "open used in Other"},
		{"open as a value", "internal/state/a.go", st("func OpenUser() { f := open; _ = f }"), "open used in OpenUser"},
		{"package-level key", "internal/state/a.go", st("var k = newMACKey(nil)"), "newMACKey used outside a function"},
		{"newMACKey elsewhere", "internal/state/a.go", st("func record() { _ = newMACKey(nil) }"), "newMACKey used in record"},
		{"key literal", "internal/state/a.go", st("func record() { _ = macKey{b: nil} }"), "macKey literal in record"},
		{"store literal", "internal/state/a.go", st("func record() { _ = &Store{} }"), "Store literal in record"},
		{"new store", "internal/state/a.go", st("func record() { _ = new(Store) }"), "Store literal in record"},
		{"key assigned", "internal/state/a.go", st("func record(s *Store, k macKey) { s.key = k }"), "key assigned in record"},
		{"key bytes assigned", "internal/state/a.go", st("func record(k *macKey) { k.b = nil }"), "b assigned in record"},
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

// secretProblems reports how the non-test file name could hold the test key
// or build a store with a key that did not come from OpenUser.
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
	var found []problem
	if strings.HasPrefix(name, "internal/state/") && f.Name.Name == "state" {
		found = structuralProblems(f)
	} else {
		found = importerProblems(f)
	}
	for _, p := range found {
		problems = append(problems, fmt.Sprintf("%s:%d: %s", name, fset.Position(p.pos).Line, p.why))
	}
	return problems
}

var keyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(\\x5a){32}`),
	regexp.MustCompile(`(?i)(0x5a\s*,\s*){31}0x5a`),
	regexp.MustCompile(`(\b90\s*,\s*){31}90\b`),
	regexp.MustCompile(`(?i)repeat\(\s*(\[\]byte\{\s*(0x5a|90|'Z')\s*\}|"Z"|'Z')`),
}

// keyEncoded reports the test key (32 bytes of 0x5a, "Z") as raw text, hex,
// base64, escapes, a byte list or a Repeat call.
func keyEncoded(src string) bool {
	h := hex.EncodeToString(testSecret)
	forms := []string{string(testSecret), h, strings.ToUpper(h)}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		forms = append(forms, enc.EncodeToString(testSecret))
	}
	for _, form := range forms {
		if strings.Contains(src, form) {
			return true
		}
	}
	return slices.ContainsFunc(keyPatterns, func(re *regexp.Regexp) bool { return re.MatchString(src) })
}

type problem struct {
	pos token.Pos
	why string
}

// importerProblems checks a file outside package state: it may not reach
// OpenWithSecret, build a Store or Run itself, or hide either behind a dot
// import.
func importerProblems(f *ast.File) []problem {
	pkg := ""
	for _, spec := range f.Imports {
		if p, _ := strconv.Unquote(spec.Path.Value); p != statePkg {
			continue
		}
		pkg = "state"
		if spec.Name != nil {
			pkg = spec.Name.Name
		}
		if pkg == "." {
			return []problem{{spec.Pos(), "dot import of internal/state hides its names from this check"}}
		}
	}
	if pkg == "" {
		return nil
	}
	var problems []problem
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if isPkgName(x, pkg, "OpenWithSecret") {
				problems = append(problems, problem{x.Pos(), "OpenWithSecret outside tests: use state.OpenUser"})
			}
		case *ast.CompositeLit:
			if isPkgName(x.Type, pkg, "Store") || isPkgName(x.Type, pkg, "Run") {
				problems = append(problems, problem{x.Pos(), "state literal outside the package"})
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 &&
				(isPkgName(x.Args[0], pkg, "Store") || isPkgName(x.Args[0], pkg, "Run")) {
				problems = append(problems, problem{x.Pos(), "state literal outside the package"})
			}
		}
		return true
	})
	return problems
}

func isPkgName(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg && sel.Sel.Name == name
}
