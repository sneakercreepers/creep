package testapps

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
)

const appsDir = "testdata/apps"

// runnerExts are files a shell, make or a CI runner executes.
var runnerExts = map[string]bool{".sh": true, ".bash": true, ".ps1": true, ".bat": true, ".cmd": true, ".mk": true}

// processImports are the packages Go code can start a program with.
var processImports = map[string]bool{"os/exec": true, "syscall": true, "golang.org/x/sys/unix": true, "golang.org/x/sys/windows": true}

// checkNoExecution reports every file in fsys (a repository root) that could
// run the apps under appsDir: an executed file that mentions the directory,
// or Go code that can start programs and names it.
func checkNoExecution(fsys fs.FS) ([]string, error) {
	var problems []string
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return skipWalk(fsys, name, d)
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		if why := executesApps(name, data); why != "" {
			problems = append(problems, fmt.Sprintf("%s: %s; the apps under %s run only in the sandbox", name, why, appsDir))
		}
		return nil
	})
	return problems, err
}

// skipWalk leaves out .git, the apps themselves, the recorded replies under
// testdata/replay, the root build outputs and nested modules, such as a git
// worktree checked out inside the repository, which are not this
// repository's files. Every other testdata tree is checked: a script under
// internal/<pkg>/testdata can name ../../../testdata/apps too.
func skipWalk(fsys fs.FS, name string, d fs.DirEntry) error {
	switch {
	case name == ".":
		return nil
	case d.Name() == ".git", name == appsDir, name == "testdata/replay":
		return fs.SkipDir
	case path.Dir(name) == "." && (d.Name() == "bin" || d.Name() == "dist"):
		return fs.SkipDir
	}
	if _, err := fs.Stat(fsys, path.Join(name, "go.mod")); err == nil {
		return fs.SkipDir
	}
	return nil
}

func executesApps(name string, data []byte) string {
	if path.Ext(name) == ".go" {
		return goExecutesApps(name, data)
	}
	if isRunnerFile(name) && mentionsApps(string(data)) {
		return "an executed file mentions the vulnerable apps"
	}
	return ""
}

// runnerNames are lower-case base names that make, just, npm, a dev
// container or a GitHub action runs.
var runnerNames = map[string]bool{
	"makefile": true, "gnumakefile": true, "justfile": true, ".justfile": true,
	"package.json": true, "action.yml": true, "action.yaml": true, ".devcontainer.json": true,
}

// isRunnerFile ignores case: GNU make reads makefile, and the Windows and
// macOS file systems treat Dockerfile and dockerfile as one file.
func isRunnerFile(name string) bool {
	name = strings.ToLower(name)
	base, dir := path.Base(name), path.Dir(name)
	switch {
	case runnerNames[base], runnerExts[path.Ext(base)]:
		return true
	case strings.HasPrefix(base, "dockerfile"), strings.HasPrefix(base, "containerfile"):
		return true
	case dir == ".github/workflows", isRunnerYAML(base):
		return true
	case base == "tasks.json" && path.Base(dir) == ".vscode":
		return true
	}
	return slices.Contains(strings.Split(dir, "/"), ".devcontainer")
}

// isRunnerYAML matches the YAML files a tool runs commands from: docker
// compose (docker-compose*, compose*), Task (taskfile*), pre-commit and
// GoReleaser hooks.
func isRunnerYAML(base string) bool {
	ext := path.Ext(base)
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	for _, prefix := range []string{"docker-compose", "compose", "taskfile", ".pre-commit-config", ".goreleaser"} {
		if strings.HasPrefix(base, prefix) {
			return true
		}
	}
	return false
}

// mentionsApps matches the path with either separator, so a Windows script
// cannot spell it with backslashes to slip past.
func mentionsApps(s string) bool {
	s = strings.ToLower(strings.ReplaceAll(s, `\`, "/"))
	return strings.Contains(s, appsDir)
}

// goExecutesApps reports a //go:generate directive naming the apps, which
// `go generate` runs whatever the file imports, and Go code that can start a
// program and has a string literal naming the apps: the whole path, or
// "apps" for a filepath.Join.
func goExecutesApps(name string, data []byte) string {
	file, err := parser.ParseFile(token.NewFileSet(), name, data, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		return fmt.Sprintf("cannot parse: %v", err)
	}
	if generatesApps(file) {
		return "a //go:generate directive names the vulnerable apps"
	}
	if !startsPrograms(file) {
		return ""
	}
	found := ""
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || found != "" {
			return found == ""
		}
		if s, err := strconv.Unquote(lit.Value); err == nil && (mentionsApps(s) || strings.Trim(s, `/\`) == "apps") {
			found = "Go code that can start programs names the vulnerable apps"
		}
		return true
	})
	return found
}

// generatesApps also matches an indented directive, which go generate
// ignores, so the guard errs on the side of flagging.
func generatesApps(file *ast.File) bool {
	for _, group := range file.Comments {
		for _, c := range group.List {
			if strings.HasPrefix(c.Text, "//go:generate") && mentionsApps(c.Text) {
				return true
			}
		}
	}
	return false
}

func startsPrograms(file *ast.File) bool {
	for _, spec := range file.Imports {
		if imp, err := strconv.Unquote(spec.Path.Value); err == nil && processImports[imp] {
			return true
		}
	}
	calls := false
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "StartProcess" {
			calls = true
		}
		return !calls
	})
	return calls
}
