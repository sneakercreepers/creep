package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
)

// listedPackage is the subset of `go list -json` the reachability checks need.
type listedPackage struct {
	ImportPath     string
	Standard       bool
	Dir            string
	GoFiles        []string
	CgoFiles       []string
	IgnoredGoFiles []string
	NonGoFiles     []string `json:"-"` // assembly, .syso, C and the like; see nonGoFiles
	Imports        []string
	TestImports    []string
	XTestImports   []string
	Module         *struct {
		Path string
		Main bool
	}
}

// nonGoFiles are the `go list -json` lists of files that are not Go source.
// Assembly or a .syso can make system calls with no import at all.
type nonGoFiles struct {
	SFiles, SysoFiles, CFiles, CXXFiles, MFiles, HFiles, FFiles []string
	SwigFiles, SwigCXXFiles, IgnoredOtherFiles                  []string
}

func (n nonGoFiles) all() []string {
	return slices.Concat(n.SFiles, n.SysoFiles, n.CFiles, n.CXXFiles, n.MFiles, n.HFiles, n.FFiles,
		n.SwigFiles, n.SwigCXXFiles, n.IgnoredOtherFiles)
}

// buildTarget is one configuration whose import graph the reach checks walk.
type buildTarget struct{ goos, goarch, cgo string }

func (t buildTarget) env() []string {
	return []string{"GOOS=" + t.goos, "GOARCH=" + t.goarch, "CGO_ENABLED=" + t.cgo}
}

// reachTargets are every release build (.goreleaser.yaml: goos × goarch with
// CGO_ENABLED=0; TestReachTargetsMatchRelease fails when they drift) and the
// Linux CI job, which tests with cgo on. A file whose build constraints match
// none of them (freebsd, a custom tag) is outside the graph; it reaches no
// shipped binary and no CI run.
var reachTargets = []buildTarget{
	{"linux", "amd64", "0"}, {"linux", "arm64", "0"},
	{"darwin", "amd64", "0"}, {"darwin", "arm64", "0"},
	{"windows", "amd64", "0"}, {"windows", "arm64", "0"},
	{"linux", "amd64", "1"},
}

// listPackages merges `go list -deps -test -json ./...` over every reachTarget.
// The listings are independent go processes, so they run in parallel.
func listPackages(root string) (map[string]listedPackage, error) {
	outs := make([][]byte, len(reachTargets))
	errs := make([]error, len(reachTargets))
	var wg sync.WaitGroup
	for i, t := range reachTargets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i], errs[i] = goOutputEnv(root, t.env(), "list", "-deps", "-test", "-json", "./...")
		}()
	}
	wg.Wait()
	merged := map[string]listedPackage{}
	for i, t := range reachTargets {
		if err := mergeListing(merged, outs[i], errs[i]); err != nil {
			return nil, fmt.Errorf("%s: %w", strings.Join(t.env(), " "), err)
		}
	}
	return merged, nil
}

func mergeListing(merged map[string]listedPackage, out []byte, err error) error {
	if err != nil {
		return err
	}
	pkgs, err := decodePackages(out)
	if err != nil {
		return err
	}
	for name, p := range pkgs {
		merged[name] = mergePackage(merged[name], p)
	}
	return nil
}

// mergePackage unions the file and import lists of one package listed for two targets.
func mergePackage(have, p listedPackage) listedPackage {
	if have.ImportPath == "" {
		return p
	}
	have.GoFiles = union(have.GoFiles, p.GoFiles)
	have.CgoFiles = union(have.CgoFiles, p.CgoFiles)
	have.IgnoredGoFiles = union(have.IgnoredGoFiles, p.IgnoredGoFiles)
	have.NonGoFiles = union(have.NonGoFiles, p.NonGoFiles)
	have.Imports = union(have.Imports, p.Imports)
	have.TestImports = union(have.TestImports, p.TestImports)
	have.XTestImports = union(have.XTestImports, p.XTestImports)
	return have
}

// union appends the entries of b missing from a, keeping a's order.
func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// decodePackages reads the JSON stream `go list -json` prints, dropping the
// test variants ("p [p.test]", "p.test") that -test adds.
func decodePackages(data []byte) (map[string]listedPackage, error) {
	pkgs := map[string]listedPackage{}
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var p struct {
			listedPackage
			nonGoFiles
		}
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			return pkgs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parse go list -json: %w", err)
		}
		if strings.Contains(p.ImportPath, " ") || strings.HasSuffix(p.ImportPath, ".test") {
			continue
		}
		p.NonGoFiles = p.all()
		pkgs[p.ImportPath] = p.listedPackage
	}
}
