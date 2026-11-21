package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

const repoRoot = "../../.."

// TestProtectionsAreRequired pins the wiring of #17: every test the
// Makefile's protections target names exists in a package the target runs
// (a renamed or moved test would otherwise match nothing and pass), CI runs
// the target as the protections job, and the main ruleset requires that job.
func TestProtectionsAreRequired(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")
	names := strings.Split(makeVar(t, makefile, "PROTECTION_TESTS"), "|")
	pkgs := strings.Fields(makeVar(t, makefile, "PROTECTION_PKGS"))
	missing, err := missingTests(os.DirFS(repoRoot), names, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range missing {
		t.Errorf("Makefile PROTECTION_TESTS names %s, which no _test.go file in PROTECTION_PKGS defines", name)
	}
	ci := readRepoFile(t, ".github/workflows/ci.yml")
	if !regexp.MustCompile(`(?m)^  protections:\n(    .*\n|\n)*?      - run: make protections$`).MatchString(strings.ReplaceAll(ci, "\r\n", "\n")) {
		t.Error("ci.yml: no protections job running make protections")
	}
	if !requiredCheck(t, "protections") {
		t.Error(".github/rulesets/main.json: protections is not a required status check")
	}
}

// TestMissingTests shows the name check failing for each test the
// protections target would not run.
func TestMissingTests(t *testing.T) {
	fsys := fstest.MapFS{
		"internal/a/a_test.go":     {Data: []byte("package a\n\nfunc TestListed(t *testing.T) {}\nfunc FuzzListed(f *testing.F) {}\n")},
		"internal/a/a.go":          {Data: []byte("package a\n\nfunc TestNotATestFile(t *testing.T) {}\n")},
		"internal/a/sub/s_test.go": {Data: []byte("package sub\n\nfunc TestInSubpackage(t *testing.T) {}\n")},
		"internal/b/b_test.go":     {Data: []byte("package b\n\nfunc TestUnlisted(t *testing.T) {}\n")},
	}
	tests := []struct {
		name string
		pkgs []string
		want string
	}{
		{"TestListed", []string{"./internal/a"}, ""},
		{"FuzzListed", []string{"./internal/a"}, ""},
		{"TestUnlisted", []string{"./internal/a"}, "TestUnlisted"},
		{"TestInSubpackage", []string{"./internal/a"}, "TestInSubpackage"},
		{"TestNotATestFile", []string{"./internal/a"}, "TestNotATestFile"},
		{"TestGone", []string{"./internal/a", "./internal/b"}, "TestGone"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			missing, err := missingTests(fsys, []string{tt.name}, tt.pkgs)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(missing, ","); got != tt.want {
				t.Errorf("missing = %q, want %q", got, tt.want)
			}
		})
	}
	if _, err := missingTests(fsys, []string{"TestListed"}, []string{"./internal/gone"}); err == nil {
		t.Error("a listed package that does not exist was accepted")
	}
}

func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// makeVar returns the value of the Makefile line "name := value".
func makeVar(t *testing.T, makefile, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + name + `\s*:=\s*(\S.*?)\s*$`).FindStringSubmatch(makefile)
	if m == nil {
		t.Fatalf("Makefile: no %s", name)
	}
	return m[1]
}

// missingTests returns the names that no top-level Test or Fuzz function
// in the pkgs' own _test.go files defines. go test runs a listed package
// alone, never its subpackages, so those do not count.
func missingTests(fsys fs.FS, names, pkgs []string) ([]string, error) {
	decl := regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)\w+)\(`)
	defined := map[string]bool{}
	for _, pkg := range pkgs {
		dir := strings.TrimPrefix(pkg, "./")
		entries, err := fs.ReadDir(fsys, dir)
		if err != nil {
			return nil, fmt.Errorf("protection package %s: %w", pkg, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			data, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", e.Name(), err)
			}
			for _, m := range decl.FindAllStringSubmatch(string(data), -1) {
				defined[m[1]] = true
			}
		}
	}
	var missing []string
	for _, name := range names {
		if !defined[name] {
			missing = append(missing, name)
		}
	}
	return missing, nil
}

func requiredCheck(t *testing.T, context string) bool {
	t.Helper()
	var rs struct {
		Rules []struct {
			Type       string
			Parameters struct {
				Checks []struct{ Context string } `json:"required_status_checks"`
			}
		}
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, ".github/rulesets/main.json")), &rs); err != nil {
		t.Fatal(err)
	}
	for _, r := range rs.Rules {
		for _, c := range r.Parameters.Checks {
			if r.Type == "required_status_checks" && c.Context == context {
				return true
			}
		}
	}
	return false
}
