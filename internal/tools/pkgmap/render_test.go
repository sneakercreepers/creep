package main

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestSynopsis(t *testing.T) {
	tests := []struct {
		name    string
		files   fstest.MapFS
		want    string
		wantErr string
	}{
		{
			name:  "first sentence",
			files: fstest.MapFS{"a/doc.go": {Data: []byte("// Package a does one thing.\n//\n// More detail.\npackage a\n")}},
			want:  "Package a does one thing.",
		},
		{
			name:  "sentence over two lines",
			files: fstest.MapFS{"a/doc.go": {Data: []byte("// Package a does one\n// thing. Then more.\npackage a\n")}},
			want:  "Package a does one thing.",
		},
		{
			name:    "missing doc.go",
			files:   fstest.MapFS{"a/a.go": {Data: []byte("// Package a is documented elsewhere.\npackage a\n")}},
			wantErr: "every package needs a doc.go",
		},
		{
			name:    "no package comment",
			files:   fstest.MapFS{"a/doc.go": {Data: []byte("package a\n")}},
			wantErr: "has no package comment",
		},
		{
			name:    "comment detached from the clause",
			files:   fstest.MapFS{"a/doc.go": {Data: []byte("// Package a floats.\n\npackage a\n")}},
			wantErr: "has no package comment",
		},
		{
			name:    "copyright only",
			files:   fstest.MapFS{"a/doc.go": {Data: []byte("// Copyright 2026 someone.\npackage a\n")}},
			wantErr: "no first sentence",
		},
		{
			name:    "not Go",
			files:   fstest.MapFS{"a/doc.go": {Data: []byte("// Package a.\npackage\n")}},
			wantErr: "parse a/doc.go",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := synopsis(tt.files, "a")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("synopsis = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestDescribe(t *testing.T) {
	documented := func(name string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte("// Package " + name + " exists.\npackage " + name + "\n")}
	}
	rows := []layerRow{{"0", "internal/a"}, {"-", "internal/tools/*"}}
	tests := []struct {
		name     string
		files    fstest.MapFS
		dirs     []string
		want     []string // "<dir> <layer>"
		wantErrs []string
	}{
		{
			name:  "exact and wildcard rows",
			files: fstest.MapFS{"internal/a/doc.go": documented("a"), "internal/tools/x/doc.go": documented("x")},
			dirs:  []string{"internal/a", "internal/tools/x"},
			want:  []string{"internal/a 0", "internal/tools/x -"},
		},
		{
			name:     "wildcard does not cover its own prefix",
			files:    fstest.MapFS{"internal/tools/doc.go": documented("tools"), "internal/toolsx/doc.go": documented("toolsx")},
			dirs:     []string{"internal/tools", "internal/toolsx"},
			wantErrs: []string{"internal/tools has no row", "internal/toolsx has no row"},
		},
		{
			name:     "every missing doc.go reported at once",
			files:    fstest.MapFS{"internal/a/a.go": documented("a"), "internal/tools/x/x.go": documented("x")},
			dirs:     []string{"internal/a", "internal/tools/x"},
			wantErrs: []string{"internal/a: every package needs a doc.go", "internal/tools/x: every package needs a doc.go"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, err := describe(tt.files, tt.dirs, rows)
			for _, want := range tt.wantErrs {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("err = %v, want it to contain %q", err, want)
				}
			}
			if len(tt.wantErrs) == 0 && err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, p := range pkgs {
				got = append(got, p.dir+" "+p.layer)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("rows = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseLayers(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		want    []layerRow
		wantErr string
	}{
		{
			name: "rows and comments",
			doc:  "x\n```layers\n# layer package\n0 internal/a -\n\n- internal/tools/* (tooling) # why\n```\n",
			want: []layerRow{{"0", "internal/a"}, {"-", "internal/tools/*"}},
		},
		{name: "no block", doc: "# Architecture\n", wantErr: "no closed"},
		{name: "unclosed block", doc: "```layers\n0 internal/a -\n", wantErr: "no closed"},
		{name: "row without package", doc: "```layers\n0\n```", wantErr: "want"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLayers(tt.doc)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || len(got) != len(tt.want) {
				t.Fatalf("rows = %v, %v; want %v", got, err, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("row %d = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestRender(t *testing.T) {
	pkgs := []pkgInfo{
		{dir: "internal/tools/z", layer: "-", purpose: "Command z is tooling."},
		{dir: "cmd/creep", layer: "7", purpose: "Command creep runs."},
		{dir: "internal/b", layer: "10", purpose: "Package b sits high."},
		{dir: "internal/a", layer: "0", purpose: "Package a | pipes\nand lines."},
		{dir: "internal/0", layer: "0", purpose: "Package zero sorts by path."},
	}
	got := string(render(pkgs))
	if !strings.HasPrefix(got, mapHeader) {
		t.Fatal("render lost the header")
	}
	want := strings.Join([]string{
		"| 0 | [`internal/0`](../internal/0/doc.go) | Package zero sorts by path. |",
		"| 0 | [`internal/a`](../internal/a/doc.go) | Package a \\| pipes and lines. |",
		"| 7 | [`cmd/creep`](../cmd/creep/doc.go) | Command creep runs. |",
		"| 10 | [`internal/b`](../internal/b/doc.go) | Package b sits high. |",
		"| - | [`internal/tools/z`](../internal/tools/z/doc.go) | Command z is tooling. |",
		"",
	}, "\n")
	if rows := strings.TrimPrefix(got, mapHeader); rows != want {
		t.Errorf("rows:\n%s\nwant:\n%s", rows, want)
	}
	if again := string(render(pkgs)); again != got {
		t.Error("render is not deterministic")
	}
}

func TestParseList(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		want    []string
		wantErr string
	}{
		{name: "root and nested", out: "m.example m.example\nm.example m.example/internal/a\n", want: []string{".", "internal/a"}},
		{name: "windows line ends", out: "m.example m.example/a\r\nm.example m.example/b\r\n", want: []string{"a", "b"}},
		{name: "empty", out: "", wantErr: "unexpected line"},
		{name: "no module", out: " m.example/a\n", wantErr: "unexpected line"},
		{name: "outside the module", out: "m.example other.example/a\n", wantErr: "outside module"},
		{name: "prefix that is not a path element", out: "m.example m.examplex/a\n", wantErr: "outside module"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseList([]byte(tt.out))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("dirs = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}
