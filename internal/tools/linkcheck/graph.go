package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// target is one release build.
type target struct{ goos, goarch string }

func (t target) name() string { return t.goos + "/" + t.goarch }

// releaseList reads a flow list such as `goos: [linux, darwin]`.
var releaseList = regexp.MustCompile(`(?m)^\s*(?:-\s+)?(goos|goarch):\s*\[([^\]]*)\]`)

// releaseTargets are goos × goarch of the one build in .goreleaser.yaml,
// read each run so a new platform is checked the day it ships. Anything
// but one list of each fails closed.
func releaseTargets(release string) ([]target, error) {
	lists := map[string][]string{}
	for _, m := range releaseList.FindAllStringSubmatch(release, -1) {
		if _, dup := lists[m[1]]; dup {
			return nil, fmt.Errorf(".goreleaser.yaml has more than one %s list", m[1])
		}
		for _, v := range strings.Split(m[2], ",") {
			lists[m[1]] = append(lists[m[1]], strings.TrimSpace(v))
		}
	}
	if len(lists["goos"]) == 0 || len(lists["goarch"]) == 0 {
		return nil, fmt.Errorf(".goreleaser.yaml: no goos or goarch list")
	}
	var targets []target
	for _, goos := range lists["goos"] {
		for _, goarch := range lists["goarch"] {
			targets = append(targets, target{goos, goarch})
		}
	}
	return targets, nil
}

// linkGraph is the linker's reachability graph: from -> the symbols it
// keeps alive (go build -ldflags=-dumpdep).
type linkGraph map[string][]string

// releaseLinkGraphs links cmd/creep for every target, in parallel, as the
// release does: cgo off, -trimpath.
func releaseLinkGraphs(root string, targets []target) ([]linkGraph, error) {
	dir, err := os.MkdirTemp("", "creep-linkcheck-")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)
	graphs := make([]linkGraph, len(targets))
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Go(func() { graphs[i], errs[i] = dumpLinkGraph(root, t, filepath.Join(dir, "creep-"+t.goos+"-"+t.goarch)) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("link %s: %w", targets[i].name(), err)
		}
	}
	return graphs, nil
}

// dumpLinkGraph links without inlining (-gcflags=all=-l): an inlined
// function's calls are charged to its caller, so a third-party call
// inlined into creep's code, or a syscall wrapper inlined into the
// third-party caller, would hide the edge (v0.3 tester T1).
func dumpLinkGraph(root string, t target, out string) (linkGraph, error) {
	cmd := exec.Command("go", "build", "-trimpath", "-gcflags=all=-l", "-ldflags=-dumpdep", "-o", out, "./cmd/creep") //nolint:gosec // G204: fixed arguments; out is our own temp file
	cmd.Dir = root
	// A go.work above the root must not change what is linked.
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "GOOS="+t.goos, "GOARCH="+t.goarch)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w\n%s", err, lastBytes(stderr.Bytes(), 4<<10))
	}
	return parseLinkGraph(&stderr)
}

// lastBytes is the end of a long build log, where go puts the error.
func lastBytes(b []byte, n int) []byte {
	return bytes.TrimSpace(b[max(len(b)-n, 0):])
}

// parseLinkGraph reads -dumpdep's "from -> to" lines; any other line is
// the go command's own output. No edge at all fails closed: a linker that
// changed its output would otherwise pass every check.
func parseLinkGraph(r *bytes.Buffer) (linkGraph, error) {
	g := linkGraph{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		from, to, ok := strings.Cut(sc.Text(), " -> ")
		if ok {
			g[from] = append(g[from], strings.TrimSuffix(to, " <UsedInIface>"))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read -dumpdep: %w", err)
	}
	if len(g) == 0 {
		return nil, fmt.Errorf("-dumpdep printed no edges")
	}
	return g, nil
}
