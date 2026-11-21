package main

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const fixtureLayers = "```layers\n0 internal/a -\n1 internal/b a\n- internal/tools/* (tooling)\n```\n"

// writeModule lays out a module in a temp dir: go.mod, the layers document
// and the given files (slash paths).
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	all := map[string]string{
		"go.mod":               "module m.example\n\ngo 1.22\n",
		"docs/architecture.md": fixtureLayers,
	}
	for name, data := range files {
		all[name] = data
	}
	for name, data := range all {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func docGo(pkg string) string { return "// Package " + pkg + " exists.\npackage " + pkg + "\n" }

// TestGenerateListsOnlyModulePackages pins what go list leaves out: agent
// worktrees under .claude/, other dot and underscore directories, testdata
// and nested modules. None of them has a doc.go, so listing one would fail.
func TestGenerateListsOnlyModulePackages(t *testing.T) {
	root := writeModule(t, map[string]string{
		"internal/a/doc.go":                   docGo("a"),
		"internal/b/doc.go":                   docGo("b"),
		"internal/b/b_test.go":                "package b\n",
		".claude/worktrees/w/internal/c/c.go": "package c\n",
		".claude/worktrees/w/go.mod":          "module m.example\n\ngo 1.22\n",
		".hidden/d/d.go":                      "package d\n",
		"_skip/e/e.go":                        "package e\n",
		"internal/a/testdata/f/f.go":          "package f\n",
		"nested/go.mod":                       "module m.example/nested\n\ngo 1.22\n",
		"nested/g/g.go":                       "package g\n",
		"internal/tools/gen/doc.go":           docGo("main"),
		"internal/tools/gen/testdata/h/h.go":  "package h\n",
	})
	out, err := generate(config{root: root, out: "docs/map.md", architecture: "docs/architecture.md"})
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.TrimPrefix(string(out), mapHeader)
	want := "| 0 | [`internal/a`](../internal/a/doc.go) | Package a exists. |\n" +
		"| 1 | [`internal/b`](../internal/b/doc.go) | Package b exists. |\n" +
		"| - | [`internal/tools/gen`](../internal/tools/gen/doc.go) | Package main exists. |\n"
	if rows != want {
		t.Errorf("map rows:\n%s\nwant:\n%s", rows, want)
	}
}

// TestGenerateIsTheSameOnEveryHost pins #117: packages are listed for every
// release platform with cgo off, whatever GOOS, GOARCH and C toolchain the
// host has, so each CI job builds the same map.
func TestGenerateIsTheSameOnEveryHost(t *testing.T) {
	// A host without a C toolchain turns cgo off by itself; force it on so
	// the cgo case fails on every host when pkgmap stops turning it off.
	t.Setenv("CGO_ENABLED", "1")
	only := func(constraint, pkg string) string { return "//go:build " + constraint + "\n\n" + docGo(pkg) }
	tests := []struct {
		name  string
		files map[string]string
		want  []string // tooling packages listed besides internal/a
	}{
		{name: "linux only", files: map[string]string{"internal/tools/l/doc.go": only("linux", "l")}, want: []string{"l"}},
		{name: "windows only", files: map[string]string{"internal/tools/w/doc.go": only("windows", "w")}, want: []string{"w"}},
		{name: "darwin only", files: map[string]string{"internal/tools/d/doc.go": only("darwin", "d")}, want: []string{"d"}},
		{name: "linux by file name", files: map[string]string{"internal/tools/n/doc.go": only("linux", "n"), "internal/tools/n/n_linux.go": "package n\n"}, want: []string{"n"}},
		{name: "arm64 only", files: map[string]string{"internal/tools/r/doc.go": only("arm64", "r")}, want: []string{"r"}},
		{name: "every OS at once", files: map[string]string{
			"internal/tools/l/doc.go": only("linux", "l"), "internal/tools/w/doc.go": only("windows", "w"), "internal/tools/d/doc.go": only("darwin", "d"),
		}, want: []string{"d", "l", "w"}},
		{name: "cgo only is never listed", files: map[string]string{"internal/tools/c/doc.go": only("cgo", "c")}},
		{name: "unix outside the targets is never listed", files: map[string]string{"internal/tools/f/doc.go": only("freebsd", "f")}},
		{name: "ignored is never listed", files: map[string]string{"internal/tools/i/doc.go": only("ignore", "i")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.files["internal/a/doc.go"] = docGo("a")
			out, err := generate(config{root: writeModule(t, tt.files), out: "docs/map.md", architecture: "docs/architecture.md"})
			if err != nil {
				t.Fatal(err)
			}
			want := mapHeader + "| 0 | [`internal/a`](../internal/a/doc.go) | Package a exists. |\n"
			for _, p := range tt.want {
				want += "| - | [`internal/tools/" + p + "`](../internal/tools/" + p + "/doc.go) | Package " + p + " exists. |\n"
			}
			if string(out) != want {
				t.Errorf("map:\n%s\nwant:\n%s", out, want)
			}
		})
	}
}

func TestGenerateFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		wantErr string
	}{
		{name: "package without doc.go", files: map[string]string{"internal/a/a.go": docGo("a")}, wantErr: "internal/a: every package needs a doc.go"},
		{name: "package without a layers row", files: map[string]string{"internal/z/doc.go": docGo("z")}, wantErr: "internal/z has no row"},
		{name: "no layers block", files: map[string]string{"internal/a/doc.go": docGo("a"), "docs/architecture.md": "# none\n"}, wantErr: "docs/architecture.md: no closed"},
		{name: "two packages in one directory", files: map[string]string{"internal/a/doc.go": docGo("a"), "internal/a/b.go": "package b\n"}, wantErr: "go list"},
		{name: "two packages on one platform only", files: map[string]string{"internal/a/doc.go": docGo("a"), "internal/a/b_windows.go": "package b\n"}, wantErr: "GOOS=windows GOARCH=amd64"},
		{name: "doc.go missing on one platform only", files: map[string]string{"internal/a/doc.go": docGo("a"), "internal/tools/l/l_linux.go": "package l\n"}, wantErr: "internal/tools/l: every package needs a doc.go"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeModule(t, tt.files)
			var out bytes.Buffer
			code := run(config{root: root, out: "docs/map.md", architecture: "docs/architecture.md"}, &out)
			if code != 2 || !strings.Contains(out.String(), tt.wantErr) {
				t.Fatalf("run = %d, %q; want 2 and %q", code, out.String(), tt.wantErr)
			}
			if _, err := os.Stat(filepath.Join(root, "docs", "map.md")); err == nil {
				t.Error("a failed run wrote the map")
			}
		})
	}
}

func TestCheckDetectsStaleMap(t *testing.T) {
	root := writeModule(t, map[string]string{"internal/a/doc.go": docGo("a")})
	cfg := config{root: root, out: "docs/map.md", architecture: "docs/architecture.md"}
	mapFile := filepath.Join(root, "docs", "map.md")
	check := func(t *testing.T, want int) {
		t.Helper()
		var out bytes.Buffer
		cfg := cfg
		cfg.check = true
		if code := run(cfg, &out); code != want {
			t.Fatalf("check = %d (%s), want %d", code, strings.TrimSpace(out.String()), want)
		}
	}
	steps := []struct {
		name   string
		change func(t *testing.T)
		want   int
	}{
		{name: "missing map", change: func(*testing.T) {}, want: 1},
		{name: "fresh map", change: func(t *testing.T) { mustRun(t, cfg) }, want: 0},
		{name: "CRLF checkout", change: func(t *testing.T) {
			rewrite(t, mapFile, func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") })
		}, want: 0},
		{name: "hand edit", change: func(t *testing.T) { rewrite(t, mapFile, func(s string) string { return s + "extra\n" }) }, want: 1},
		{name: "regenerated", change: func(t *testing.T) { mustRun(t, cfg) }, want: 0},
		{name: "new package", change: func(t *testing.T) { writeFile(t, filepath.Join(root, "internal", "b", "doc.go"), docGo("b")) }, want: 1},
		{name: "regenerated again", change: func(t *testing.T) { mustRun(t, cfg) }, want: 0},
		{name: "changed purpose", change: func(t *testing.T) {
			writeFile(t, filepath.Join(root, "internal", "a", "doc.go"), "// Package a changed.\npackage a\n")
		}, want: 1},
	}
	for _, s := range steps {
		s.change(t)
		t.Run(s.name, func(t *testing.T) { check(t, s.want) })
	}
}

func mustRun(t *testing.T, cfg config) {
	t.Helper()
	var out bytes.Buffer
	if code := run(cfg, &out); code != 0 {
		t.Fatalf("run = %d: %s", code, out.String())
	}
}

func writeFile(t *testing.T, name, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rewrite(t *testing.T, name string, edit func(string) string) {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, name, edit(string(data)))
}

// TestMakeCheckRunsMapCheck pins the CI wiring: the test job runs
// `make check`, which must fail on a stale map.
func TestMakeCheckRunsMapCheck(t *testing.T) {
	data, err := os.ReadFile("../../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, re := range []string{
		`(?m)^check:[^\n]*\smap-check(\s|$)`,
		`(?m)^map-check:\r?\n\tgo run \./internal/tools/pkgmap -check\s*$`,
		`(?m)^map:\r?\n\tgo run \./internal/tools/pkgmap\s*$`,
	} {
		if !regexp.MustCompile(re).Match(data) {
			t.Errorf("Makefile does not match %s", re)
		}
	}
}

// releaseList matches a goos or goarch flow list in .goreleaser.yaml.
var releaseList = regexp.MustCompile(`(?m)^\s*(goos|goarch):\s*\[([^\]]*)\]`)

// TestMapPlatformsMatchRelease fails when the release builds for a platform
// mapPlatforms does not list, or no longer builds for one it lists (#117).
// make budget guards its reachTargets the same way.
func TestMapPlatformsMatchRelease(t *testing.T) {
	data, err := os.ReadFile("../../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	release := string(data)
	if !strings.Contains(release, "- CGO_ENABLED=0") {
		t.Error(".goreleaser.yaml no longer builds with CGO_ENABLED=0; update goList")
	}
	lists := map[string][][]string{}
	for _, m := range releaseList.FindAllStringSubmatch(release, -1) {
		lists[m[1]] = append(lists[m[1]], strings.FieldsFunc(m[2], func(r rune) bool { return r == ',' || r == ' ' }))
	}
	if len(lists["goos"]) != 1 || len(lists["goarch"]) != 1 {
		t.Fatalf(".goreleaser.yaml goos/goarch lists = %q, want one build", lists)
	}
	want := map[[2]string]bool{}
	for _, goos := range lists["goos"][0] {
		for _, goarch := range lists["goarch"][0] {
			want[[2]string{goos, goarch}] = true
		}
	}
	got := map[[2]string]bool{}
	for _, p := range mapPlatforms {
		got[p] = true
	}
	if !maps.Equal(got, want) || len(got) != len(mapPlatforms) {
		t.Errorf("mapPlatforms = %v, want the release targets %v", mapPlatforms, want)
	}
}
