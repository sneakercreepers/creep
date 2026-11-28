package calibrate

import (
	"io/fs"
	"math"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Every class has the same number of templates, so Generate's round robin
// gives each class the same number of tasks (8, tier.go), and every
// template contributes at least one pair to a run.
func TestEmbeddedCatalogCoversEveryClass(t *testing.T) {
	cat, err := defaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	perClass := map[Class]int{}
	for _, tpl := range cat.templates {
		perClass[tpl.class]++
	}
	for _, c := range Classes() {
		if perClass[c] == 0 || perClass[c] != perClass[Classes()[0]] {
			t.Errorf("class %s has %d templates; every class needs the same nonzero count (%v)", c, perClass[c], perClass)
		}
	}
	if TaskCount%(2*len(cat.templates)) != 0 {
		t.Errorf("%d templates do not split %d tasks into whole pairs", len(cat.templates), TaskCount)
	}
}

// languageWords are source languages, runtimes and frameworks a task set
// written for one language would name. ADR 0037: the calibration task set
// names none of them, so it measures the same on every repository.
var languageWords = regexp.MustCompile(`(?i)\b(python|javascript|typescript|java|golang|rust|ruby|php|kotlin|swift|csharp|scala|perl|elixir|haskell|node|nodejs|deno|flask|django|fastapi|express|spring|rails|laravel|sqlite3|subprocess|pickle|yaml|jinja2?|require|import|def|const|function|var)\b`)

// Acceptance (#358): no language name appears in the calibration task set:
// not in a template, a filler, the task prompt or any generated task.
func TestTaskSetNamesNoLanguage(t *testing.T) {
	err := fs.WalkDir(embeddedTemplates, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(embeddedTemplates, path)
		if m := languageWords.FindString(string(data)); err == nil && m != "" {
			t.Errorf("%s names %q", path, m)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if m := languageWords.FindString(taskSystem); m != "" {
		t.Errorf("task prompt names %q", m)
	}
	for _, seed := range []uint64{0, 1, math.MaxUint64} {
		for _, task := range mustGenerate(t, seed) {
			if m := languageWords.FindString(task.Code + task.Template); m != "" {
				t.Errorf("seed %d %s (%s) names %q", seed, task.ID, task.Template, m)
			}
		}
	}
}

func TestLanguageWordsCatchPerLanguageCode(t *testing.T) {
	for _, code := range []string{
		"import sqlite3", "from flask import Flask", `const express = require("express");`,
		"def find(): pass", "package main // golang", "Python", "pickle.loads(raw)",
	} {
		if !languageWords.MatchString(code) {
			t.Errorf("%q is not caught", code)
		}
	}
}

// unsafeCalls run caller text as code or a command, or rebuild typed
// objects: no safe twin calls one.
var unsafeCalls = []string{"shell(", "eval(", "make_function(", "deserialize_object("}

// A safe twin has no defensible finding in any class (#162). No safe twin
// makes an unsafe call or compiles a template from anything but a string
// literal. A twin that keeps the vulnerable sink has a guard that refuses
// other input, and every line from it down to the sink is checked, so
// caller input cannot come back on a line that builds the sink's argument;
// a twin without a guard fixes the sink line itself.
func TestSafeTwinsCleanInEveryClass(t *testing.T) {
	cat, err := defaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	renderLiteral := regexp.MustCompile(`templates\.render\(([^"]|$)`)
	for _, tpl := range cat.templates {
		code := strings.Join(tpl.safe.lines, "\n")
		for _, call := range unsafeCalls {
			if strings.Contains(code, call) {
				t.Errorf("%s safe twin calls %s", tpl.id, call)
			}
		}
		if renderLiteral.MatchString(code) {
			t.Errorf("%s safe twin renders a template that is not a string literal", tpl.id)
		}
	}
	checked := map[string]bool{}
	for _, tt := range guardedTwins() {
		checked[tt.id] = true
		t.Run(tt.id, func(t *testing.T) { checkGuardedTwin(t, cat, tt) })
	}
	for id, sink := range unguardedTwins() {
		checked[id] = true
		v := templateByID(t, cat, id).safe
		if line := v.lines[v.sinkLine-1]; !strings.Contains(line, sink) {
			t.Errorf("%s safe sink line %q lacks %q", id, line, sink)
		}
	}
	for _, tpl := range cat.templates {
		if !checked[tpl.id] {
			t.Errorf("%s safe twin is not checked", tpl.id)
		}
	}
}

type guardedTwin struct {
	id        string
	guard     string   // the last line before the sink that refuses other input
	forbidden []string // caller input that must not appear after the guard
	flowHas   []string // what must reach the sink after the guard
}

// guardedTwins send the sink only an allowlisted value, the value that was
// checked (a pattern with no separator or leading dash, a path confined to
// its root, a URL with host and port fixed) or a function from a fixed map.
func guardedTwins() []guardedTwin {
	return []guardedTwin{
		{"sqli-order", "if column not in [", []string{"request."}, []string{`ORDER BY " + column`, "db.query(sql)"}},
		{"command-lookup", "if domain not in [", []string{"request."}, []string{`run_process(["nslookup", domain])`}},
		{"command-git", "if not matches(branch,", []string{"request."}, []string{`run_process(["git", "log", "--oneline", branch])`}},
		{"path-read", "if not starts_with(path,", []string{"request.", "join("}, []string{"read_file(path)"}},
		{"path-write", "if not matches(stored,", []string{"request.", "upload.filename"}, []string{"+ stored", "write_file(target,"}},
		{"ssrf-url", "address.port != none", []string{"request.", "address.host", "address.scheme"}, []string{`http_get(url_of("https", "images.example.invalid", address.path))`}},
		{"ssrf-webhook", "if requested not in [", []string{"request."}, []string{`url_of("https", requested, "/notify")`, "http_post(endpoint,"}},
		{"code-compile", "if scorer == none", []string{"request.", "formula"}, []string{"scorer(10)"}},
	}
}

// unguardedTwins fix the sink line: a bound parameter, a value converted
// to a string or a number, a literal template, plain JSON.
func unguardedTwins() map[string]string {
	return map[string]string{
		"sqli-concat":        "db.query(sql, [term])",
		"nosql-find-one":     `{"@@field@@": name}`,
		"nosql-filter":       `mongo.find("@@coll@@", criteria)`,
		"template-concat":    `templates.render("Dear {{ who }}`,
		"template-note":      `templates.render("{{ user }}: {{ note }}"`,
		"code-eval":          "to_number(expression)",
		"deserialize-cookie": "parse_json(raw)",
		"deserialize-job":    "parse_json(request.body())",
	}
}

func checkGuardedTwin(t *testing.T, cat catalog, tt guardedTwin) {
	t.Helper()
	flow, ok := sinkFlow(templateByID(t, cat, tt.id).safe, tt.guard)
	if !ok {
		t.Fatalf("safe twin lacks the guard %q before its sink", tt.guard)
	}
	for _, bad := range tt.forbidden {
		if strings.Contains(flow, bad) {
			t.Errorf("caller input %q reaches the sink after the guard:\n%s", bad, flow)
		}
	}
	for _, want := range tt.flowHas {
		if !strings.Contains(flow, want) {
			t.Errorf("sink flow lacks %q:\n%s", want, flow)
		}
	}
}

func templateByID(t *testing.T, cat catalog, id string) template {
	t.Helper()
	i := slices.IndexFunc(cat.templates, func(tpl template) bool { return tpl.id == id })
	if i < 0 {
		t.Fatalf("no template %s", id)
	}
	return cat.templates[i]
}

// sinkFlow returns the lines after the last guard line before the sink,
// through the sink.
func sinkFlow(v variant, guard string) (string, bool) {
	for g := v.sinkLine - 2; g >= 0; g-- {
		if strings.Contains(v.lines[g], guard) {
			return strings.Join(v.lines[g+1:v.sinkLine], "\n"), true
		}
	}
	return "", false
}
