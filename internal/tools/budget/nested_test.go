package main

import (
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

const gitdirPointer = "gitdir: /elsewhere/.git/worktrees/agent\n"

func TestSkipDir(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/worktrees/agent/.git":   {Data: []byte(gitdirPointer)},
		".claude/worktrees/agent/go.mod": {Data: []byte("module example.com/m\n")},
		"clone/.git/HEAD":                {Data: []byte("ref: refs/heads/main\n")},
		"clone/go.mod":                   {Data: []byte("module example.com/other\n")},
		"internal/planted/.git":          {Data: []byte(gitdirPointer)},
		"internal/planted/p.go":          {Data: []byte("package planted\n")},
		"internal/gomoddir/.git":         {Data: []byte(gitdirPointer)},
		"internal/gomoddir/go.mod/x":     {Data: []byte("not a go.mod file\n")},
		"sub/go.mod":                     {Data: []byte("module example.com/sub\n")},
		"internal/bin/b.go":              {Data: []byte("package bin\n")},
		"bin/out":                        {},
		"internal/a/testdata/x.go":       {},
		"internal/a/a.go":                {Data: []byte("package a\n")},
	}
	tests := []struct {
		name string
		dir  string
		want bool
	}{
		{"root is always walked", ".", false},
		{"agent worktree: .git file and go.mod", ".claude/worktrees/agent", true},
		{"nested clone: .git dir and go.mod", "clone", true},
		{"planted .git without go.mod stays checked", "internal/planted", false},
		{"go.mod that is a directory is no module", "internal/gomoddir", false},
		{"committable nested go.mod stays checked", "sub", false},
		{"the .claude dir itself stays checked", ".claude", false},
		{"ordinary package", "internal/a", false},
		{"testdata anywhere", "internal/a/testdata", true},
		{"root bin", "bin", true},
		{"nested bin is a package", "internal/bin", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := fs.Stat(fsys, tt.dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := skipDir(fsys, tt.dir, fs.FileInfoToDirEntry(info)); got != tt.want {
				t.Errorf("skipDir(%q) = %v, want %v", tt.dir, got, tt.want)
			}
		})
	}
}

// TestNestedWorktreeDoesNotAffectBudget writes a repo whose nested agent
// worktree breaks every walked rule, next to product code that tries to hide
// behind a planted .git or a committable go.mod. Only the worktree is skipped.
func TestNestedWorktreeDoesNotAffectBudget(t *testing.T) {
	const wt = ".claude/worktrees/agent/"
	root := writeTree(t, map[string]string{
		"go.mod":                     "module example.com/m\n\ngo 1.24\n",
		"internal/a/a.go":            "package a\n",
		wt + ".git":                  gitdirPointer,
		wt + "go.mod":                "module example.com/m\n\ngo 1.24\n",
		wt + "internal/x/x.go":       "package x\nimport _ \"net/http\"\n",
		wt + "internal/x/x_amd64.s":  "TEXT f(SB)\n",
		wt + "tools/action.yml":      "    - uses: actions/checkout@v7\n",
		"internal/planted/.git":      gitdirPointer,
		"internal/planted/p.go":      "package planted\nimport _ \"net/http\"\n",
		"internal/planted/p_amd64.s": "TEXT f(SB)\n",
		"sub/go.mod":                 "module example.com/sub\n\ngo 1.24\n",
		"sub/action.yml":             "    - uses: evil/action@main\n",
	})
	fsys := os.DirFS(root)

	files, err := collectSources(fsys, testMod)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
	}
	if want := []string{"internal/a/a.go", "internal/planted/p.go"}; !reflect.DeepEqual(names, want) {
		t.Errorf("collectSources walked %q, want %q", names, want)
	}

	foreign, err := walkForeignFiles(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"internal/planted/p_amd64.s"}; !reflect.DeepEqual(foreign, want) {
		t.Errorf("walkForeignFiles = %q, want %q", foreign, want)
	}

	workflows, err := workflowProblems(config{root: root})
	if err != nil {
		t.Fatal(err)
	}
	assertMentions(t, workflows, []string{"sub/action.yml"})
	for _, p := range workflows {
		if strings.Contains(p, ".claude") {
			t.Errorf("worktree workflow reported: %q", p)
		}
	}
}
