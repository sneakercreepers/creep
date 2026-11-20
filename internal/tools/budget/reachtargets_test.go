package main

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestProcessBypassModule runs the reach step over a throwaway module with go
// list, so each PR #42 audit bypass and every build target are covered end
// to end. The dependency is a local replace only so the fixture needs no
// network; the workspace check, not this step, rejects that.
func TestProcessBypassModule(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":                     "module example.com/m\n\ngo 1.24\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./dep\n",
		"dep/go.mod":                 "module example.com/dep\n\ngo 1.24\n",
		"dep/raw/raw.go":             "package raw\n",
		"dep/raw/raw_plan9.go":       "//go:build plan9\n\npackage raw\nimport _ \"syscall\"\n",
		"dep/asm/asm.go":             "package asm\n\nfunc Getpid() int\n",
		"dep/asm/asm_amd64.s":        "TEXT ·Getpid(SB),0,$0\n\tSYSCALL\n\tRET\n",
		"dep/syso/syso.go":           "package syso\n",
		"dep/syso/blob.syso":         "\x7fELF",
		"dep/clean/clean.go":         "package clean\nimport _ \"strings\"\n",
		"internal/tools/run/run.go":  "package run\nimport _ \"os/exec\"\n",
		"internal/cli/cli.go":        "package cli\nimport _ \"example.com/m/internal/tools/run\"\n",
		"internal/gen/gen.go":        "package gen\nimport _ \"go/build\"\n",
		"internal/mac/mac_darwin.go": "package mac\nimport _ \"go/importer\"\n",
		"internal/dep/dep.go":        "package dep\nimport _ \"example.com/dep/raw\"\n",
		"internal/sys/sys.go":        "package sys\nimport (\n\t_ \"example.com/dep/asm\"\n\t_ \"example.com/dep/syso\"\n)\n",
		"internal/ok/ok.go":          "package ok\nimport _ \"example.com/dep/clean\"\n",
		// Each file below is seen only by some targets, and each package also
		// exists on the others, so the merge of listings must keep the import.
		"internal/arm/arm.go":            "package arm\n",
		"internal/arm/arm_arm64.go":      "package arm\nimport _ \"go/build\"\n",
		"internal/nocgo/nocgo.go":        "package nocgo\n",
		"internal/nocgo/nocgo_off.go":    "//go:build !cgo\n\npackage nocgo\nimport _ \"go/build\"\n",
		"internal/withcgo/withcgo.go":    "package withcgo\n",
		"internal/withcgo/withcgo_on.go": "//go:build cgo\n\npackage withcgo\nimport _ \"go/build\"\n",
		"internal/win/win.go":            "package win\n",
		"internal/win/win_darwin.go":     "package win\nimport _ \"go/build\"\n",
		"internal/wt/wt.go":              "package wt\n",
		"internal/wt/wt_windows_test.go": "package wt\nimport _ \"go/build\"\n",
		"internal/xt/xt.go":              "package xt\n",
		"internal/xt/xt_darwin_test.go":  "package xt_test\nimport _ \"go/build\"\n",
	})
	got, err := reachProblems(config{root: root})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/arm reaches a process start through go/build",
		"internal/cli reaches a process start through example.com/m/internal/tools/run",
		`internal/dep reaches a process start through example.com/dep/raw: raw_plan9.go imports "syscall"`,
		"internal/gen reaches a process start through go/build",
		"internal/mac reaches a process start through go/importer",
		"internal/nocgo reaches a process start through go/build",
		"internal/sys reaches a process start through example.com/dep/asm: asm_amd64.s is not Go",
		"internal/sys reaches a process start through example.com/dep/syso: blob.syso is not Go",
		"internal/win reaches a process start through go/build",
		"internal/withcgo reaches a process start through go/build",
		"internal/wt (tests) reaches a process start through go/build",
		"internal/xt (tests) reaches a process start through go/build",
	}
	assertMentions(t, got, want)
}

// A reviewed package on nonGoAllowed passes; any other with non-Go files does not.
func TestNonGoAllowed(t *testing.T) {
	saved := nonGoAllowed
	t.Cleanup(func() { nonGoAllowed = saved })
	nonGoAllowed = map[string]string{"example.com/reviewed": "fixture"}
	for _, tt := range []struct{ pkg, want string }{{"example.com/reviewed", ""}, {"example.com/other", "a.s is not Go"}} {
		why, err := starterReason(listedPackage{ImportPath: tt.pkg, Dir: t.TempDir(), NonGoFiles: []string{"a.s"}})
		if err != nil {
			t.Fatal(err)
		}
		if (tt.want == "") != (why == "") || !strings.Contains(why, tt.want) {
			t.Errorf("%s: starterReason() = %q, want %q", tt.pkg, why, tt.want)
		}
	}
}

// Every list a later target adds survives the merge, in order and without
// duplicates; the first listing is taken whole.
func TestMergePackage(t *testing.T) {
	a := listedPackage{ImportPath: "p", Dir: "d", GoFiles: []string{"a.go"}, CgoFiles: []string{"c.go"}, IgnoredGoFiles: []string{"i.go"},
		NonGoFiles: []string{"a.s"}, Imports: []string{"x"}, TestImports: []string{"tx"}, XTestImports: []string{"xx"}}
	b := listedPackage{ImportPath: "p", Dir: "d", GoFiles: []string{"b.go", "a.go"}, CgoFiles: []string{"d.go"}, IgnoredGoFiles: []string{"j.go"},
		NonGoFiles: []string{"b.syso"}, Imports: []string{"y", "x"}, TestImports: []string{"ty"}, XTestImports: []string{"xy"}}
	want := listedPackage{ImportPath: "p", Dir: "d", GoFiles: []string{"a.go", "b.go"}, CgoFiles: []string{"c.go", "d.go"},
		IgnoredGoFiles: []string{"i.go", "j.go"}, NonGoFiles: []string{"a.s", "b.syso"}, Imports: []string{"x", "y"},
		TestImports: []string{"tx", "ty"}, XTestImports: []string{"xx", "xy"}}
	if got := mergePackage(a, b); !reflect.DeepEqual(got, want) {
		t.Errorf("mergePackage() = %+v, want %+v", got, want)
	}
	if got := mergePackage(listedPackage{}, b); !reflect.DeepEqual(got, b) {
		t.Errorf("first listing = %+v, want %+v", got, b)
	}
}

// decodePackages keeps every non-Go file list go list prints.
func TestDecodePackagesNonGoFiles(t *testing.T) {
	data := `{"ImportPath":"p","SFiles":["a.s"],"SysoFiles":["b.syso"],"CFiles":["c.c"],"CXXFiles":["d.cc"],"MFiles":["e.m"],` +
		`"HFiles":["f.h"],"FFiles":["g.f"],"SwigFiles":["h.swig"],"SwigCXXFiles":["i.swigcxx"],"IgnoredOtherFiles":["j_plan9.s"]}`
	pkgs, err := decodePackages([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.s", "b.syso", "c.c", "d.cc", "e.m", "f.h", "g.f", "h.swig", "i.swigcxx", "j_plan9.s"}
	if got := pkgs["p"].NonGoFiles; !reflect.DeepEqual(got, want) {
		t.Errorf("NonGoFiles = %q, want %q", got, want)
	}
}

var flowList = regexp.MustCompile(`(?m)^\s*(goos|goarch|os):\s*\[([^\]]*)\]`)

// The reach targets must be the release matrix and the CI jobs; this fails
// when .goreleaser.yaml or the CI matrix changes shape without them.
func TestReachTargetsMatchRelease(t *testing.T) {
	release := readRepoFile(t, ".goreleaser.yaml")
	for _, why := range releaseShapeProblems(release) {
		t.Error(why)
	}
	lists := flowLists(release)
	if len(lists["goos"]) != 1 || len(lists["goarch"]) != 1 {
		t.Fatalf(".goreleaser.yaml goos/goarch lists = %q, want one build", lists)
	}
	var want []buildTarget
	for _, goos := range lists["goos"][0] {
		for _, goarch := range lists["goarch"][0] {
			want = append(want, buildTarget{goos, goarch, "0"})
		}
	}
	// The Linux CI job tests with cgo on; the Windows one with it off, a release target.
	want = append(want, buildTarget{"linux", "amd64", "1"})
	if ci := flowLists(readRepoFile(t, ".github/workflows/ci.yml"))["os"]; !reflect.DeepEqual(ci, [][]string{{"ubuntu-latest", "windows-latest"}}) {
		t.Errorf("ci.yml test matrix = %q; update reachTargets for the new runners", ci)
	}
	if !sameTargets(reachTargets, want) {
		t.Errorf("reachTargets = %v, want %v", reachTargets, want)
	}
}

// releaseShapes change which files a release build compiles beyond goos ×
// goarch, so reachTargets would no longer match the release.
var releaseShapes = []string{"ignore:", "targets:", "goarm:", "goamd64:", "goarm64:", "tags:", "-tags"}

func releaseShapeProblems(release string) []string {
	var problems []string
	for _, shape := range releaseShapes {
		if strings.Contains(release, shape) {
			problems = append(problems, fmt.Sprintf(".goreleaser.yaml uses %q; update reachTargets and this test", shape))
		}
	}
	if !strings.Contains(release, "- CGO_ENABLED=0") {
		problems = append(problems, ".goreleaser.yaml no longer builds with CGO_ENABLED=0; update reachTargets")
	}
	return problems
}

// Each release-config shape that changes the compiled files is drift.
func TestReleaseShapeProblems(t *testing.T) {
	base := "builds:\n  - env:\n      - CGO_ENABLED=0\n    goos: [linux]\n    goarch: [amd64]\n"
	tests := []struct {
		name string
		doc  string
		want string // substring of the single problem; "" means no drift
	}{
		{"plain matrix", base, ""},
		{"build tags in flags", base + "    flags:\n      - -trimpath\n      - -tags=creepx\n", `uses "-tags"`},
		{"build tags as a separate flag", base + "    flags: [-tags, creepx]\n", `uses "-tags"`},
		{"tags key", base + "    tags: [creepx]\n", `uses "tags:"`},
		{"ignored target", base + "    ignore:\n      - goos: linux\n", `uses "ignore:"`},
		{"explicit targets", base + "    targets: [linux_amd64]\n", `uses "targets:"`},
		{"amd64 level", base + "    goamd64: [v3]\n", `uses "goamd64:"`},
		{"arm64 level", base + "    goarm64: [v9.0]\n", `uses "goarm64:"`},
		{"arm level", base + "    goarm: [7]\n", `uses "goarm:"`},
		{"cgo on", strings.Replace(base, "CGO_ENABLED=0", "CGO_ENABLED=1", 1), "no longer builds with CGO_ENABLED=0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertOneProblem(t, releaseShapeProblems(tt.doc), tt.want)
		})
	}
}

// A failed or unreadable listing stops the reach step; it is never merged as
// an empty graph that passes.
func TestMergeListingFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		out  string
		err  error
	}{
		{"go list failed", `{"ImportPath":"p"}`, errors.New("go list: exit status 1")},
		{"malformed output", `{"ImportPath":`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merged := map[string]listedPackage{}
			if err := mergeListing(merged, []byte(tt.out), tt.err); err == nil {
				t.Errorf("mergeListing() succeeded, merged %v", merged)
			}
		})
	}
}

// A target whose go list fails fails the whole step, named in the error.
func TestListPackagesFailsClosed(t *testing.T) {
	root := writeTree(t, map[string]string{"go.mod": "module example.com/m\n\ngo 1.24\n", "a/a.go": "package a\nimport _ \"example.com/m/missing\"\n"})
	if _, err := listPackages(root); err == nil || !strings.Contains(err.Error(), "GOOS=") {
		t.Errorf("listPackages() error = %v, want the failing target named", err)
	}
}

func flowLists(doc string) map[string][][]string {
	lists := map[string][][]string{}
	for _, m := range flowList.FindAllStringSubmatch(doc, -1) {
		var items []string
		for _, item := range strings.Split(m[2], ",") {
			items = append(items, strings.Trim(strings.TrimSpace(item), `"'`))
		}
		lists[m[1]] = append(lists[m[1]], items)
	}
	return lists
}

func sameTargets(a, b []buildTarget) bool {
	return len(a) == len(b) && !slices.ContainsFunc(a, func(t buildTarget) bool { return !slices.Contains(b, t) })
}
