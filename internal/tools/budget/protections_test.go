package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const repoRoot = "../../.."

// TestProtectionsAreRequired pins the wiring of #17: every test the
// Makefile's protections target names exists (a renamed test would
// otherwise match nothing and pass), CI runs the target as the protections
// job, and the main ruleset requires that job.
func TestProtectionsAreRequired(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")
	m := regexp.MustCompile(`(?m)^PROTECTION_TESTS\s*:=\s*(\S+)\s*$`).FindStringSubmatch(makefile)
	if m == nil {
		t.Fatal("Makefile: no PROTECTION_TESTS")
	}
	defined := testFuncs(t)
	for _, name := range strings.Split(m[1], "|") {
		if !defined[name] {
			t.Errorf("Makefile PROTECTION_TESTS names %s, which no _test.go file defines", name)
		}
	}
	ci := readRepoFile(t, ".github/workflows/ci.yml")
	if !regexp.MustCompile(`(?m)^  protections:\n(    .*\n|\n)*?      - run: make protections$`).MatchString(strings.ReplaceAll(ci, "\r\n", "\n")) {
		t.Error("ci.yml: no protections job running make protections")
	}
	if !requiredCheck(t, "protections") {
		t.Error(".github/rulesets/main.json: protections is not a required status check")
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

// testFuncs returns the names of every top-level Test and Fuzz function
// in the module's _test.go files.
func testFuncs(t *testing.T) map[string]bool {
	t.Helper()
	decl := regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)\w+)\(`)
	names := map[string]bool{}
	fsys := os.DirFS(repoRoot)
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".claude" || d.Name() == "testdata") {
			return fs.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		for _, m := range decl.FindAllStringSubmatch(string(data), -1) {
			names[m[1]] = true
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
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
