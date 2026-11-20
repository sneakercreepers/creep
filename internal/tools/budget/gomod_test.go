package main

import (
	"testing"
)

func replace(oldPath, newPath, version string) modReplace {
	r := modReplace{}
	r.Old.Path, r.New.Path, r.New.Version = oldPath, newPath, version
	return r
}

// A versioned replace that swaps in another module needs that module's ADR (#45).
func TestCheckReplaces(t *testing.T) {
	allow := map[string]string{"example.com/fork": "docs/adr/0001-ok.md", "example.com/gone": "docs/adr/0002-gone.md"}
	exists := func(p string) bool { return p == "docs/adr/0001-ok.md" }
	tests := []struct {
		name string
		r    modReplace
		want string // substring of the single problem; "" means allowed
	}{
		{"remote fork", replace("example.com/x", "github.com/other/x", "v1.0.0"), "replaces example.com/x with github.com/other/x v1.0.0, which has no ADR"},
		{"fork of an allowlisted module", replace("example.com/fork", "github.com/other/fork", "v1.0.0"), "has no ADR"},
		{"fork with its own ADR", replace("example.com/x", "example.com/fork", "v1.0.0"), ""},
		{"fork whose ADR is missing", replace("example.com/x", "example.com/gone", "v1.0.0"), "ADR docs/adr/0002-gone.md does not exist"},
		{"same module, other version", replace("example.com/x", "example.com/x", "v1.2.3"), ""},
		{"local path is the workspace check's", replace("example.com/x", "../x", ""), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertOneProblem(t, checkReplaces([]modReplace{tt.r}, allow, exists), tt.want)
		})
	}
}

// A tool's module needs an ADR even when go.mod marks it indirect (#46).
func TestToolModules(t *testing.T) {
	tests := []struct {
		name    string
		tool    string
		want    string // module the tool resolves to
		problem string // substring of the single problem
	}{
		{"tool in a required module", "example.com/x/cmd/gen", "example.com/x", ""},
		{"longest module wins", "example.com/x/sub/cmd/gen", "example.com/x/sub", ""},
		{"module root is the tool", "example.com/x", "example.com/x", ""},
		{"main module tool", "example.com/m/internal/tools/gen", "", ""},
		{"prefix look-alike is not the module", "example.com/xy/gen", "", "no required module provides it"},
		{"no module", "example.com/ghost/gen", "", "no required module provides it"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mf := modFile{Require: []modRequire{{Path: "example.com/x", Indirect: true}, {Path: "example.com/x/sub", Indirect: true}}}
			mf.Module.Path = "example.com/m"
			mf.Tool = []struct{ Path string }{{tt.tool}}
			mods, problems := toolModules(mf)
			assertOneProblem(t, problems, tt.problem)
			if got := firstOr(mods); got != tt.want {
				t.Errorf("module = %q, want %q", got, tt.want)
			}
		})
	}
}

func firstOr(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// depProblems reads tool and replace directives through `go mod edit -json`,
// so each acceptance case fails the real step.
func TestDepProblemsModDirectives(t *testing.T) {
	const allowlist = "docs/adr/dependencies.txt"
	tests := []struct {
		name  string
		gomod string
		want  []string
	}{
		{"unlisted indirect tool", "require example.com/gen v1.0.0 // indirect\n\ntool example.com/gen/cmd/gen\n", []string{"direct dependency example.com/gen has no ADR"}},
		{"listed tool", "require example.com/ok v1.0.0 // indirect\n\ntool example.com/ok/cmd/gen\n", nil},
		{"tool without a module", "tool example.com/ghost/cmd/gen\n", []string{"tool example.com/ghost/cmd/gen: no required module provides it"}},
		{"versioned remote replace", "require example.com/ok v1.0.0\n\nreplace example.com/ok => github.com/other/x v1.0.0\n", []string{"replaces example.com/ok with github.com/other/x v1.0.0"}},
		{"tool and direct require report once", "require example.com/gen v1.0.0\n\ntool example.com/gen/cmd/gen\n", []string{"direct dependency example.com/gen has no ADR"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"go.mod":              "module example.com/m\n\ngo 1.24\n\n" + tt.gomod,
				allowlist:             "example.com/ok docs/adr/0001-ok.md\n",
				"docs/adr/0001-ok.md": "# ok\n",
			})
			got, err := depProblems(config{root: root, allowlist: allowlist})
			if err != nil {
				t.Fatal(err)
			}
			assertMentions(t, got, tt.want)
		})
	}
}
