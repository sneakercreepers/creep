package calibrate

import (
	"strings"
	"testing"
	"testing/fstest"
)

const (
	testFillers = `{"version": 2, "lines": ["let PAGE_SIZE = 50"]}`
	testSpec    = `{
  "version": 2, "id": "test-sqli", "class": "sqli", "pad_after": 1,
  "slots": {"func": ["alpha", "beta"]},
  "vulnerable": {"sink_line": 3, "marker": "run(sql)"},
  "safe": {"sink_line": 3, "marker": "run(sql, ["}
}`
	testVuln = "let TABLE = \"notes\"\nhandler @@func@@(sql):\n    return db.run(sql)\n"
	testSafe = "let TABLE = \"notes\"\nhandler @@func@@(sql):\n    return db.run(sql, [])\n"
)

// testFS is a valid one-template catalog with edit applied to template.json.
func testFS(edit func(spec, vuln, safe string) (string, string, string)) fstest.MapFS {
	spec, vuln, safe := testSpec, testVuln, testSafe
	if edit != nil {
		spec, vuln, safe = edit(spec, vuln, safe)
	}
	return fstest.MapFS{
		"fillers.json":              {Data: []byte(testFillers)},
		"test-sqli/template.json":   {Data: []byte(spec)},
		"test-sqli/vulnerable.tmpl": {Data: []byte(vuln)},
		"test-sqli/safe.tmpl":       {Data: []byte(safe)},
	}
}

func specEdit(old, repl string) func(string, string, string) (string, string, string) {
	return func(spec, vuln, safe string) (string, string, string) {
		return strings.Replace(spec, old, repl, 1), vuln, safe
	}
}

func TestLoadCatalogAcceptsCRLF(t *testing.T) {
	fsys := testFS(func(spec, vuln, safe string) (string, string, string) {
		return spec, strings.ReplaceAll(vuln, "\n", "\r\n"), strings.ReplaceAll(safe, "\n", "\r\n")
	})
	crlf, err := loadCatalog(fsys)
	if err != nil {
		t.Fatal(err)
	}
	lf, err := loadCatalog(testFS(nil))
	if err != nil {
		t.Fatal(err)
	}
	m := mutation{values: map[string]string{"func": "alpha"}}
	if a, b := render(crlf.templates[0], true, m), render(lf.templates[0], true, m); a != b {
		t.Errorf("CRLF template renders differently:\n%q\n%q", a.Code, b.Code)
	}
}

func TestLoadCatalogRejects(t *testing.T) {
	tests := []struct {
		name string
		edit func(string, string, string) (string, string, string)
		want string
	}{
		{"unknown field", specEdit(`"version": 2,`, `"version": 2, "extra": 1,`), "unknown field"},
		// #358: a template names no language, and a v1 per-language
		// template is refused, not read as neutral.
		{"language field", specEdit(`"version": 2,`, `"version": 2, "language": "python",`), "unknown field"},
		{"v1 template", specEdit(`"version": 2`, `"version": 1`), "version 1"},
		{"id differs from directory", specEdit(`"test-sqli"`, `"test-other"`), "directory name"},
		{"unknown class", specEdit(`"sqli"`, `"xss"`), "unknown class"},
		{"class not read by a scan", specEdit(`"sqli"`, `"idor"`), "unknown class"},
		{"value is a builtin", specEdit(`"beta"`, `"shell"`), "keyword"},
		{"value is a sink builtin", specEdit(`"beta"`, `"deserialize_object"`), "keyword"},
		{"no slots", specEdit(`{"func": ["alpha", "beta"]}`, `{}`), "no slots"},
		{"pool of one", specEdit(`["alpha", "beta"]`, `["alpha"]`), "at least 2"},
		{"value not an identifier", specEdit(`"beta"`, `"be\"ta"`), "plain identifier"},
		{"value with a dot", specEdit(`"beta"`, `"os.system"`), "plain identifier"},
		{"value is a keyword", specEdit(`"beta"`, `"return"`), "keyword"},
		{"value aliases a template word", specEdit(`"beta"`, `"sql"`), "already appears"},
		{"value aliases a filler", specEdit(`"beta"`, `"PAGE_SIZE"`), "already appears"},
		{"value repeats across slots", func(spec, vuln, safe string) (string, string, string) {
			spec = strings.Replace(spec, `"func": ["alpha", "beta"]`, `"func": ["alpha", "beta"], "arg": ["gamma", "alpha"]`, 1)
			return spec, strings.Replace(vuln, "(sql)", "(sql, @@arg@@)", 1), safe
		}, "repeats in slot"},
		{"bad slot name", specEdit(`"func"`, `"Func"`), "lowercase"},
		{"placeholder without slot", func(spec, vuln, safe string) (string, string, string) {
			return spec, vuln + "@@other@@\n", safe
		}, "has no slot"},
		{"malformed placeholder", func(spec, vuln, safe string) (string, string, string) {
			return spec, vuln + "x = @@Func\n", safe
		}, "malformed placeholder"},
		{"unused slot", specEdit(`"func": ["alpha", "beta"]`, `"func": ["alpha", "beta"], "arg": ["gamma", "delta"]`), "never used"},
		{"sink line past the end", specEdit(`"sink_line": 3, "marker": "run(sql)"`, `"sink_line": 4, "marker": "run(sql)"`), "outside"},
		{"sink line zero", specEdit(`"sink_line": 3, "marker": "run(sql, ["`, `"sink_line": 0, "marker": "run(sql, ["`), "outside"},
		{"pad after the sink", specEdit(`"pad_after": 1`, `"pad_after": 3`), "pad_after"},
		{"negative pad", specEdit(`"pad_after": 1`, `"pad_after": -1`), "pad_after"},
		{"empty marker", specEdit(`"run(sql)"`, `""`), "literal"},
		{"marker with placeholder", specEdit(`"run(sql)"`, `"@@func@@"`), "literal"},
		{"marker missing from own code", specEdit(`"run(sql)"`, `"exec(sql)"`), "not in its code"},
		{"marker also in twin", specEdit(`"run(sql)"`, `"db.run(sql"`), "also in its twin"},
		{"empty code", func(spec, _, safe string) (string, string, string) { return spec, "\n\n", safe }, "empty"},
		{"trailing json", func(spec, vuln, safe string) (string, string, string) { return spec + "{}", vuln, safe }, "trailing data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadCatalog(testFS(tt.edit))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestLoadCatalogRejectsBadFillers(t *testing.T) {
	tests := map[string]string{
		"wrong version": `{"version": 3, "lines": ["let A = 1"]}`,
		"multi-line":    `{"version": 2, "lines": ["let A = 1\nlet B = 2"]}`,
		"empty line":    `{"version": 2, "lines": [""]}`,
		"placeholder":   `{"version": 2, "lines": ["let @@func@@ = 1"]}`,
		"not json":      `version: 2`,
		"no lines":      `{"version": 2, "lines": []}`,
		"lines missing": `{"version": 2}`,
		// #358: the v1 per-language filler file is refused.
		"per language": `{"version": 1, "python": ["A = 1"], "javascript": ["const A = 1;"]}`,
		"language key": `{"version": 2, "lines": ["let A = 1"], "python": ["A = 1"]}`,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			fsys := testFS(nil)
			fsys["fillers.json"] = &fstest.MapFile{Data: []byte(data)}
			if _, err := loadCatalog(fsys); err == nil {
				t.Fatal("loadCatalog accepted bad fillers")
			}
		})
	}
}

func TestLoadCatalogNeedsATemplate(t *testing.T) {
	fsys := fstest.MapFS{"fillers.json": {Data: []byte(testFillers)}}
	if _, err := loadCatalog(fsys); err == nil || !strings.Contains(err.Error(), "none found") {
		t.Fatalf("err = %v, want none found", err)
	}
}
