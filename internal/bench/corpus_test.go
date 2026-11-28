package bench

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

// calibrationTemplates is where calibration's templates live; the bench
// reads them only here, in a test, so it imports nothing to do so.
const calibrationTemplates = "../calibrate/templates"

// minSharedLine is the shortest normalized line the disjointness check
// compares: shorter lines ("}", "end", "return nil") carry no case.
const minSharedLine = 16

func TestCorpusLoads(t *testing.T) {
	cases, err := Corpus()
	if err != nil {
		t.Fatal(err)
	}
	perClass := map[string]int{}
	for _, c := range cases {
		perClass[c.Class]++
		v, s := c.Twin(Vulnerable), c.Twin(Safe)
		if bytes.Equal(v.Source, s.Source) {
			t.Errorf("%s: the twins are the same code", c.ID)
		}
		if strings.Contains(string(v.Source), "vulnerab") || strings.Contains(string(s.Source), "vulnerab") {
			t.Errorf("%s: the code names its label", c.ID)
		}
	}
	for _, class := range []string{"sqli", "command_injection", "path_traversal", "ssrf", "nosql_injection", "template_injection"} {
		if perClass[class] == 0 {
			t.Errorf("no case for readable class %s", class)
		}
	}
}

// Acceptance (#35): the bench never measures what calibration tuned on. No
// corpus line of minSharedLine or more characters, whitespace collapsed,
// matches a line of any calibration template, its @@slot@@ placeholders
// read as any identifier. Whole files are disjoint a fortiori.
func TestCorpusDisjointFromCalibration(t *testing.T) {
	templates := templateLines(t)
	if len(templates) < 100 {
		t.Fatalf("read %d template lines from %s; the layout changed", len(templates), calibrationTemplates)
	}
	err := fs.WalkDir(corpusFS, "corpus", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".src") {
			return err
		}
		data, err := corpusFS.ReadFile(p)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			if n := normalize(line); len(n) >= minSharedLine && matchesAny(templates, n) {
				t.Errorf("%s:%d is in a calibration template: %q", p, i+1, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func templateLines(t *testing.T) []*regexp.Regexp {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(calibrationTemplates, "*", "*.tmpl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no calibration templates under %s: %v", calibrationTemplates, err)
	}
	slot := regexp.MustCompile(`@@[a-z_]+@@`)
	var out []*regexp.Regexp
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			n := normalize(line)
			if n == "" {
				continue
			}
			parts := slot.Split(n, -1)
			for i := range parts {
				parts[i] = regexp.QuoteMeta(parts[i])
			}
			out = append(out, regexp.MustCompile(`^`+strings.Join(parts, `[A-Za-z0-9_]+`)+`$`))
		}
	}
	return out
}

func normalize(line string) string { return strings.Join(strings.Fields(line), " ") }

func matchesAny(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// The check itself catches a copied line, with slots filled.
func TestDisjointnessCatchesCopiedLine(t *testing.T) {
	templates := templateLines(t)
	copied := `    found = mongo.find_one("accounts", {"email": name})`
	if !matchesAny(templates, normalize(copied)) {
		t.Fatal("a line copied from nosql-find-one with its slots filled was not caught")
	}
}

func TestLoadCaseRejects(t *testing.T) {
	good := `{"version": 1, "id": "x-case", "class": "sqli", "language": "go", "file": "a.go",
"vulnerable": {"entry": "func A(", "sink": "db.Query(q)"}, "safe": {"entry": "func A(", "sink": "db.Query(\"S"}}`
	src := "package a\n\nfunc A() {\n\tdb.Query(q)\n}\n"
	safe := "package a\n\nfunc A() {\n\tdb.Query(\"SELECT 1\")\n}\n"
	tests := []struct {
		name            string
		caseJSON, vulns string
	}{
		{"version", strings.Replace(good, `"version": 1`, `"version": 2`, 1), src},
		{"unknown field", strings.Replace(good, `"version": 1,`, `"version": 1, "extra": 1,`, 1), src},
		{"id is not the directory", strings.Replace(good, `"x-case"`, `"y-case"`, 1), src},
		{"unknown class", strings.Replace(good, `"sqli"`, `"xss"`, 1), src},
		{"unknown language", strings.Replace(good, `"go"`, `"cobol"`, 1), src},
		{"file with a path", strings.Replace(good, `"a.go"`, `"../a.go"`, 1), src},
		{"marker on no line", good, strings.Replace(src, "db.Query(q)", "db.Exec(q)", 1)},
		{"marker on two lines", good, src + "// db.Query(q)\n"},
		{"entry after sink", good, "package a\n\ndb.Query(q)\nfunc A() {}\n"},
		{"source too large", good, src + strings.Repeat("x", maxSourceBytes)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"c/x-case/case.json":      {Data: []byte(tc.caseJSON)},
				"c/x-case/vulnerable.src": {Data: []byte(tc.vulns)},
				"c/x-case/safe.src":       {Data: []byte(safe)},
			}
			if _, err := loadCorpus(fsys, "c"); err == nil {
				t.Fatal("loaded")
			}
		})
	}
	fsys := fstest.MapFS{
		"c/x-case/case.json":      {Data: []byte(good)},
		"c/x-case/vulnerable.src": {Data: []byte(src)},
		"c/x-case/safe.src":       {Data: []byte(safe)},
	}
	cases, err := loadCorpus(fsys, "c")
	if err != nil || cases[0].Twin(Vulnerable).Sink != 4 || cases[0].Twin(Safe).Entry != 3 {
		t.Fatalf("good case: %+v %v", cases, err)
	}
}

func TestDigestIsStable(t *testing.T) {
	a, err := Digest()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Digest()
	if a != b || len(a) != 64 {
		t.Fatalf("digest %q then %q", a, b)
	}
}
