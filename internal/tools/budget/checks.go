package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// parseAllowlist reads "module docs/adr/NNNN-name.md" lines; '#' starts a comment.
func parseAllowlist(data []byte) (map[string]string, error) {
	allow := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 || !isADRPath(fields[1]) {
			return nil, fmt.Errorf("allowlist line %d: want \"<module> docs/adr/<file>.md\"", n)
		}
		allow[fields[0]] = fields[1]
	}
	return allow, sc.Err()
}

// checkDeps reports direct dependencies without an allowlist entry or whose ADR is missing.
func checkDeps(direct []string, allow map[string]string, adrExists func(string) bool) []string {
	var problems []string
	for _, mod := range direct {
		adr, ok := allow[mod]
		if !ok {
			problems = append(problems, fmt.Sprintf("direct dependency %s has no ADR in the allowlist", mod))
			continue
		}
		if !adrExists(adr) {
			problems = append(problems, fmt.Sprintf("direct dependency %s: ADR %s does not exist", mod, adr))
		}
	}
	return problems
}

func checkCap(what string, got, limit int64, unit string) []string {
	if got <= limit {
		return nil
	}
	return []string{fmt.Sprintf("%s is %d %s, cap is %d", what, got, unit, limit)}
}

// skipDir reports directories the budget does not own: .git and testdata
// anywhere (the go command never builds testdata), the build outputs and
// vendor tree only at the root, so a package named internal/bin is still
// checked, and nested git checkouts of other Go modules. A root vendor/ fails
// the workspace check instead.
func skipDir(fsys fs.FS, name string, d fs.DirEntry) bool {
	if !d.IsDir() || name == "." {
		return false
	}
	switch d.Name() {
	case ".git", "testdata":
		return true
	case "bin", "dist", "vendor":
		return path.Dir(name) == "."
	}
	return isNestedCheckout(fsys, name)
}

// isNestedCheckout reports a directory holding both a .git entry and its own
// go.mod, such as an agent worktree under .claude/worktrees. Both are needed:
// git refuses to track any path named .git, so such a directory never reaches
// a commit or CI, and go.mod makes it a separate module the go command does
// not build into this one. A .git alone would let a local file hide a product
// package, and a go.mod alone is committable and could hide an action.yml.
func isNestedCheckout(fsys fs.FS, name string) bool {
	if _, err := fs.Stat(fsys, path.Join(name, ".git")); err != nil {
		return false
	}
	info, err := fs.Stat(fsys, path.Join(name, "go.mod"))
	return err == nil && !info.IsDir()
}

// isADRPath accepts only clean slash paths inside docs/adr/, so an allowlist
// entry cannot point the existence check anywhere else.
func isADRPath(p string) bool {
	return strings.HasPrefix(p, "docs/adr/") && path.Clean(p) == p && !strings.Contains(p, "\\")
}
