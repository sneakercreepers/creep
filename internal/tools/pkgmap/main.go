package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type config struct {
	root         string
	out          string // map file, slash-separated and relative to root
	architecture string // holds the layers block
	check        bool
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.root, "root", ".", "module root")
	flag.StringVar(&cfg.out, "out", "docs/map.md", "map file, relative to the root")
	flag.StringVar(&cfg.architecture, "architecture", "docs/architecture.md", "document holding the layers table")
	flag.BoolVar(&cfg.check, "check", false, "fail when the map file is stale instead of writing it")
	flag.Parse()
	os.Exit(run(cfg, os.Stdout))
}

// run returns 0 when the map was written or is current, 1 when -check finds
// it stale and 2 when the map cannot be built.
func run(cfg config, out io.Writer) int {
	want, err := generate(cfg)
	if err != nil {
		fmt.Fprintln(out, "map:", err)
		return 2
	}
	if cfg.check {
		return checkFresh(cfg, want, out)
	}
	if err := os.WriteFile(cfg.path(cfg.out), want, 0o600); err != nil {
		fmt.Fprintln(out, "map:", err)
		return 2
	}
	fmt.Fprintln(out, "map: wrote", cfg.out)
	return 0
}

func (c config) path(rel string) string {
	return filepath.Join(c.root, filepath.FromSlash(rel))
}

// checkFresh compares line content only: a Windows checkout may turn the
// committed LF endings into CRLF, which is not staleness.
func checkFresh(cfg config, want []byte, out io.Writer) int {
	have, err := os.ReadFile(cfg.path(cfg.out))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(out, "map:", err)
		return 2
	}
	if bytes.Equal(bytes.ReplaceAll(have, []byte("\r\n"), []byte("\n")), want) {
		fmt.Fprintln(out, "map: ok")
		return 0
	}
	fmt.Fprintf(out, "map: %s is stale: run `make map` and commit the result\n", cfg.out)
	return 1
}

func generate(cfg config) ([]byte, error) {
	listed, err := goList(cfg.root)
	if err != nil {
		return nil, err
	}
	dirs, err := parseList(listed)
	if err != nil {
		return nil, err
	}
	arch, err := os.ReadFile(cfg.path(cfg.architecture))
	if err != nil {
		return nil, fmt.Errorf("read layers table: %w", err)
	}
	rows, err := parseLayers(string(arch))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.architecture, err)
	}
	pkgs, err := describe(os.DirFS(cfg.root), dirs, rows)
	if err != nil {
		return nil, err
	}
	return render(pkgs), nil
}

// goList prints "<module path> <import path>" for every package of the
// module rooted at root.
func goList(root string) ([]byte, error) {
	cmd := exec.Command("go", "list", "-f", "{{.Module.Path}} {{.ImportPath}}", "./...")
	cmd.Dir = root
	// A go.work above the root must not change which packages are listed.
	cmd.Env = append(os.Environ(), "GOWORK=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %w\n%s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

// parseList turns go list lines into module-relative, slash-separated
// package directories ("." for the module root).
func parseList(out []byte) ([]string, error) {
	var dirs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		mod, imp, ok := strings.Cut(strings.TrimSpace(line), " ")
		rel, under := strings.CutPrefix(imp, mod+"/")
		switch {
		case !ok || mod == "":
			return nil, fmt.Errorf("go list: unexpected line %q", line)
		case imp == mod:
			dirs = append(dirs, ".")
		case !under:
			return nil, fmt.Errorf("go list: package %s is outside module %s", imp, mod)
		default:
			dirs = append(dirs, rel)
		}
	}
	return dirs, nil
}
