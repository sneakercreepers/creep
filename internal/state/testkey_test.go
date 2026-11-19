package state

import (
	"encoding/base64"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The public test key signs committed fixtures (testdata/v1, the reader's
// replay fixtures), so a store opened with it would trust anything a
// repository plants. Three guards keep it out of production:
// OpenWithSecret refuses to run outside a go test binary
// (TestOpenWithSecretRefusedOutsideTests), keys inside this package come
// only from open (TestKeysComeOnlyFromOpen), and no non-test file holds the
// key in any common encoding (this test).
func TestNoTestKeyInProductionSources(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	files := moduleSources(t, root)
	if _, ok := files["internal/state/mac.go"]; !ok || len(files) < 50 {
		t.Fatalf("walk of %s found %d files without internal/state/mac.go", root, len(files))
	}
	for name, src := range files {
		if keyEncoded(src) {
			t.Errorf("%s holds the public test key", name)
		}
	}
}

func TestKeyEncodedCatchesEncodings(t *testing.T) {
	h := hex.EncodeToString(testSecret)
	tests := []struct {
		name, src string
		want      bool
	}{
		{"raw", strings.Repeat("Z", SecretBytes), true},
		{"hex", h, true},
		{"upper hex", strings.ToUpper(h), true},
		{"base64", base64.StdEncoding.EncodeToString(testSecret), true},
		{"raw url base64", base64.RawURLEncoding.EncodeToString(testSecret), true},
		{"escapes", strings.Repeat(`\x5A`, SecretBytes), true},
		{"byte list", "[]byte{" + strings.Repeat("0x5a, ", SecretBytes) + "}", true},
		{"decimal list", "[]byte{" + strings.Repeat("90,", SecretBytes) + "}", true},
		{"bytes.Repeat", "bytes.Repeat([]byte{'Z'}, 32)", true},
		{"strings.Repeat", `strings.Repeat( "Z", 32)`, true},
		{"other repeat", "bytes.Repeat([]byte{0x01}, 32)", false},
		{"short run", strings.Repeat("Z", SecretBytes-1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keyEncoded(tt.src); got != tt.want {
				t.Fatalf("keyEncoded = %v; want %v", got, tt.want)
			}
		})
	}
}

// Acceptance (#160, tester M1b): a production binary that reaches
// OpenWithSecret by any route (a direct call, a second import under
// another name, a function value) and passes the test key gets
// ErrTestOnly, never a store. testdata/openprobe is that binary, built
// without go test.
func TestOpenWithSecretRefusedOutsideTests(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := filepath.Join(t.TempDir(), "openprobe")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "./testdata/openprobe")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build openprobe: %v\n%s", err, out)
	}
	work := t.TempDir()
	out, err := exec.Command(bin, work).Output()
	if err != nil {
		t.Fatalf("openprobe: %v", err)
	}
	want := "direct: refused=true\nsecond import: refused=true\nfunction value: refused=true\n"
	if got := strings.ReplaceAll(string(out), "\r\n", "\n"); got != want {
		t.Fatalf("openprobe said:\n%s\nwant:\n%s", got, want)
	}
	if _, err := os.Lstat(filepath.Join(work, ".creep")); !os.IsNotExist(err) {
		t.Fatalf("a refused open created the state directory: %v", err)
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
