package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// graph builds a listing from "from>to" edges. Names under internal/ or cmd/
// are main-module packages of testMod; a "[test]" suffix on from makes the
// edge a test import.
func graph(mains []string, edges ...string) map[string]listedPackage {
	pkgs := map[string]listedPackage{}
	for _, m := range mains {
		p := listedPackage{ImportPath: modName(m)}
		p.Module = &struct {
			Path string
			Main bool
		}{testMod, true}
		pkgs[p.ImportPath] = p
	}
	for _, e := range edges {
		from, to, _ := strings.Cut(e, ">")
		name, test := strings.CutSuffix(from, "[test]")
		p := pkgs[modName(name)]
		p.ImportPath = modName(name)
		if test {
			p.TestImports = append(p.TestImports, modName(to))
		} else {
			p.Imports = append(p.Imports, modName(to))
		}
		pkgs[p.ImportPath] = p
	}
	return pkgs
}

func modName(name string) string {
	if strings.HasPrefix(name, "internal/") || strings.HasPrefix(name, "cmd/") {
		return testMod + "/" + name
	}
	return name
}

// Each row is one way for shipped code to reach a process start (#43).
func TestCheckProcessReach(t *testing.T) {
	mains := []string{"internal/cli", "internal/scanrun", "internal/tools/run", "internal/gateway", "cmd/creep", "internal/state"}
	tests := []struct {
		name     string
		edges    []string
		starters map[string]string
		want     []string
	}{
		{"wrapper library runs programs", []string{"internal/cli>example.com/wrap", "example.com/wrap>os/exec"}, nil,
			[]string{"internal/cli reaches a process start through example.com/wrap: os/exec runs programs"}},
		{"go/build runs the go command", []string{"internal/cli>go/build", "go/build>os/exec"}, nil,
			[]string{"internal/cli reaches a process start through go/build"}},
		{"go/importer through a chain", []string{"internal/cli>go/importer", "go/importer>go/internal/gcimporter", "go/internal/gcimporter>internal/exportdata", "internal/exportdata>os/exec"}, nil,
			[]string{"through go/importer: os/exec runs programs"}},
		{"helper in internal/tools", []string{"internal/cli>internal/tools/run", "internal/tools/run>os/exec"}, nil,
			[]string{"through example.com/m/internal/tools/run: internal/tools may run programs"}},
		{"third-party starter", []string{"internal/cli>example.com/raw"}, map[string]string{"example.com/raw": `r.go imports "syscall"`},
			[]string{`through example.com/raw: r.go imports "syscall"`}},
		{"starter deep in the graph", []string{"internal/cli>example.com/a", "example.com/a>example.com/raw"}, map[string]string{"example.com/raw": "r.go uses os.StartProcess"},
			[]string{"through example.com/a: r.go uses os.StartProcess"}},
		{"tests of a package that may not run programs", []string{"internal/cli[test]>os/exec"}, nil,
			[]string{"internal/cli (tests) reaches a process start through os/exec"}},
		{"import cycle ends", []string{"internal/cli>example.com/a", "example.com/a>example.com/b", "example.com/b>example.com/a"}, nil, nil},
		{"scanner runner may run programs", []string{"internal/scanrun>os/exec"}, nil, nil},
		{"product may use the scanner runner", []string{"internal/cli>internal/scanrun", "internal/scanrun>os/exec"}, nil, nil},
		{"tooling may run programs", []string{"internal/tools/run>go/build", "go/build>os/exec"}, nil, nil},
		{"gateway runs model commands", []string{"internal/gateway>os/exec"}, nil, nil},
		{"cmd/creep tests run the binary", []string{"cmd/creep[test]>os/exec"}, nil, nil},
		{"cmd/creep code may not", []string{"cmd/creep>os/exec"}, nil, []string{"cmd/creep reaches a process start through os/exec"}},
		{"state tests type-check with go/importer", []string{"internal/state[test]>go/importer", "go/importer>os/exec"}, nil, nil},
		{"plain stdlib", []string{"internal/cli>strings", "internal/cli>os", "os>syscall"}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertMentions(t, checkProcessReach(testMod, graph(mains, tt.edges...), tt.starters), tt.want)
		})
	}
}

// A third-party package counts as a starter when any file, other platforms'
// included, imports a raw-call package or names os.StartProcess.
func TestStarterReason(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string // substring of the reason; "" means no starter
	}{
		{"clean", map[string]string{"a.go": "package a\nimport \"strings\"\nvar _ = strings.ToUpper\n"}, ""},
		{"syscall", map[string]string{"a.go": "package a\nimport \"syscall\"\nvar _ = syscall.Getpid\n"}, `a.go imports "syscall"`},
		{"x/sys", map[string]string{"a.go": "package a\nimport _ \"golang.org/x/sys/unix\"\n"}, `imports "golang.org/x/sys/unix"`},
		{"unsafe linkname", map[string]string{"a.go": "package a\nimport _ \"unsafe\"\n"}, `imports "unsafe"`},
		{"os/exec", map[string]string{"a.go": "package a\nimport _ \"os/exec\"\n"}, `imports "os/exec"`},
		{"aliased StartProcess", map[string]string{"a.go": "package a\nimport o \"os\"\nvar start = o.StartProcess\n"}, "a.go uses os.StartProcess"},
		{"dot import of os", map[string]string{"a.go": "package a\nimport . \"os\"\nvar start = StartProcess\n"}, "a.go uses os.*"},
		{"other platform's file", map[string]string{"a.go": "package a\n", "z_plan9.go": "//go:build plan9\n\npackage a\nimport _ \"syscall\"\n"}, `z_plan9.go imports "syscall"`},
		{"os without starts", map[string]string{"a.go": "package a\nimport \"os\"\nvar _ = os.Getenv\n"}, ""},
		{"assembly makes system calls", map[string]string{"a.go": "package a\nfunc Getpid() int\n", "a_amd64.s": "TEXT ·Getpid(SB),0,$0\n\tSYSCALL\n"}, "a_amd64.s is not Go"},
		{"syso object", map[string]string{"a.go": "package a\n", "blob.syso": "\x7fELF"}, "blob.syso is not Go"},
		{"C source", map[string]string{"a.go": "package a\n", "x.c": "int x;\n"}, "x.c is not Go"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			p := listedPackage{ImportPath: "example.com/dep", Dir: dir}
			for name, src := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
					t.Fatal(err)
				}
				switch {
				case !strings.HasSuffix(name, ".go"):
					p.NonGoFiles = append(p.NonGoFiles, name)
				case strings.Contains(name, "plan9"):
					p.IgnoredGoFiles = append(p.IgnoredGoFiles, name)
				default:
					p.GoFiles = append(p.GoFiles, name)
				}
			}
			why, err := starterReason(p)
			if err != nil {
				t.Fatal(err)
			}
			if (tt.want == "") != (why == "") || !strings.Contains(why, tt.want) {
				t.Errorf("starterReason() = %q, want %q", why, tt.want)
			}
		})
	}
}

// A dependency the budget cannot read is an error, never a clean package.
func TestStarterReasonFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.go"), []byte("package a\nfunc {"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]listedPackage{
		"no source directory": {ImportPath: "example.com/dep"},
		"unparsable file":     {ImportPath: "example.com/dep", Dir: dir, GoFiles: []string{"bad.go"}},
		"missing file":        {ImportPath: "example.com/dep", Dir: dir, GoFiles: []string{"gone.go"}},
	}
	for name, p := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := thirdPartyStarters(map[string]listedPackage{p.ImportPath: p}); err == nil {
				t.Error("thirdPartyStarters() succeeded")
			}
		})
	}
}
