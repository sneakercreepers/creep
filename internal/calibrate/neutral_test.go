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

// languageWords are source languages, runtimes and frameworks. The code
// of the task set is held to the builtin allowlist (builtins_test.go); this
// list also covers the prose: the task prompt and template.json.
var languageWords = regexp.MustCompile(`(?i)\b(python|javascript|typescript|java|golang|rust|ruby|php|kotlin|swift|csharp|cpp|scala|perl|elixir|haskell|lua|bash|zsh|powershell|dotnet|node|nodejs|deno|flask|django|fastapi|express|spring|rails|laravel|sqlite3|subprocess|pickle|yaml|jinja2?|mongo|mongodb|require|import|def|const|function|var)\b|\bc(?:#|\+\+)`)

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
		"#!/bin/bash", "local x = 1 -- Lua", "std::system in C++", "C# code", "db.users in mongo",
	} {
		if !languageWords.MatchString(code) {
			t.Errorf("%q is not caught", code)
		}
	}
}

// A safe twin has no defensible finding in any class (#162): it calls no
// other class's dangerous builtin and compiles no template but a string
// literal. Its own class's builtin it calls behind that class's mitigation
// (TestSafeTwinsUseTheirClassMitigation).
func TestSafeTwinsCleanInEveryClass(t *testing.T) {
	cat, err := defaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	renderLiteral := regexp.MustCompile(`templates\.render\(([^"]|$)`)
	for _, tpl := range cat.templates {
		code := strings.Join(tpl.safe.lines, "\n")
		for class, sink := range classSinks {
			if class != tpl.class && sink.MatchString(code) {
				t.Errorf("%s safe twin calls %s, the %s sink", tpl.id, sink, class)
			}
		}
		if renderLiteral.MatchString(code) {
			t.Errorf("%s safe twin renders a template that is not a string literal", tpl.id)
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
