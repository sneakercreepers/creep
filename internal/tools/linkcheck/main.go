package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// linkReviewed are linker edges from third-party code into a watched
// function that were read and found harmless, each with the reason. An
// entry no release binary links any more is reported, so the list only
// shrinks.
var linkReviewed = map[string]string{
	"github.com/modelcontextprotocol/go-sdk/oauthex.newDiscoveryTransport -> net/http.(*Transport).Clone": "oauthex's package init clones http.DefaultTransport into an unused variable; only its OAuth discovery sends through it, and that code is not linked (creep's MCP server has no auth)",
}

// watchedPackages hold the functions that open connections or start
// programs; the process primitives in os and syscall are watched by name.
var (
	watchedPackages = []string{"net", "net/http", "net/rpc", "net/smtp", "os/exec", "crypto/tls"}
	watchedSymbols  = []string{"os.StartProcess", "syscall.StartProcess", "syscall.forkExec"}
)

// auxSuffixes name funcdata the linker deduplicates by content: the name
// can belong to any function with the same bytes, so it says nothing
// about who links what, and it holds no code reference.
var auxSuffixes = []string{".stkobj", ".arginfo0", ".arginfo1", ".argliveinfo", ".args_stackmap", ".opendefer", ".wrapinfo"}

func main() {
	os.Exit(run(".", os.Stdout))
}

func run(root string, out io.Writer) int {
	problems, err := collect(root)
	if err != nil {
		fmt.Fprintln(out, "linkcheck:", err)
		return 2
	}
	for _, p := range problems {
		fmt.Fprintln(out, "linkcheck:", p)
	}
	if len(problems) > 0 {
		return 1
	}
	fmt.Fprintln(out, "linkcheck: ok")
	return 0
}

func collect(root string) ([]string, error) {
	modPath, err := modulePath(root)
	if err != nil {
		return nil, err
	}
	uses, err := checkSourceUses(root)
	if err != nil {
		return nil, err
	}
	release, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		return nil, err
	}
	targets, err := releaseTargets(string(release))
	if err != nil {
		return nil, err
	}
	graphs, err := releaseLinkGraphs(root, targets)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	problems := uses
	for i, g := range graphs {
		for _, p := range checkLinkReach(modPath, g, seen) {
			problems = append(problems, targets[i].name()+": "+p)
		}
	}
	return append(problems, staleReviewed(seen)...), nil
}

var moduleLine = regexp.MustCompile(`(?m)^module\s+(\S+)\s*$`)

func modulePath(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	m := moduleLine.FindSubmatch(data)
	if m == nil {
		return "", fmt.Errorf("go.mod: no module line")
	}
	return string(m[1]), nil
}
