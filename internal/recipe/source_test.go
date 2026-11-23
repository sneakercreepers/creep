package recipe

import (
	"errors"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/reader"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

// TestParseSource: only github.com/<owner>/<repo> pinned to a full 40-hex
// commit is accepted; a branch, a tag, a short or upper-case SHA, another
// host or a path-like name is refused, and no error quotes the input.
func TestParseSource(t *testing.T) {
	tests := []struct {
		in   string
		want string // "" means refused
	}{
		{"github.com/acme/recipes@" + testCommit, "github.com/acme/recipes@" + testCommit},
		{"GitHub.com/Acme/Recipes@" + testCommit, "github.com/acme/recipes@" + testCommit},
		{"github.com/a-b/r_e.c-1@" + testCommit, "github.com/a-b/r_e.c-1@" + testCommit},
		{"github.com/acme/recipes@main", ""},
		{"github.com/acme/recipes@v1.2.0", ""},
		{"github.com/acme/recipes@refs/heads/main", ""},
		{"github.com/acme/recipes@0123456", ""},
		{"github.com/acme/recipes@" + strings.ToUpper(testCommit), ""},
		{"github.com/acme/recipes@" + testCommit + "00", ""},
		{"github.com/acme/recipes@" + strings.Repeat("0", 64), ""},
		{"github.com/acme/recipes@" + testCommit[:39] + "g", ""},
		{"github.com/acme/recipes", ""},
		{"github.com/acme/recipes@" + testCommit + "@" + testCommit, ""},
		{"gitlab.com/acme/recipes@" + testCommit, ""},
		{"https://github.com/acme/recipes@" + testCommit, ""},
		{"github.com/acme@" + testCommit, ""},
		{"github.com/acme/recipes/sub@" + testCommit, ""},
		{"github.com/-acme/recipes@" + testCommit, ""},
		{"github.com/acme/..@" + testCommit, ""},
		{"github.com/acme/.@" + testCommit, ""},
		{"github.com/ac me/recipes@" + testCommit, ""},
		{"github.com/" + strings.Repeat("a", 40) + "/r@" + testCommit, ""},
		{"github.com/acme/" + strings.Repeat("r", 101) + "@" + testCommit, ""},
		{"", ""},
	}
	for _, tt := range tests {
		src, err := ParseSource(tt.in)
		if tt.want == "" {
			if !errors.Is(err, ErrSource) {
				t.Errorf("ParseSource(%q) = %v, %v; want ErrSource", tt.in, src, err)
			}
			if err != nil && tt.in != "" && strings.Contains(err.Error(), tt.in) {
				t.Errorf("ParseSource(%q): error quotes the input: %v", tt.in, err)
			}
			continue
		}
		if err != nil || src.String() != tt.want {
			t.Errorf("ParseSource(%q) = %q, %v; want %q", tt.in, src.String(), err, tt.want)
		}
	}
}

// TestAllowlist: the policy's recipe_sources names repositories or an
// owner's repositories, compared case-insensitively; an enforced empty
// list allows nothing, and no policy list leaves it to the operator.
func TestAllowlist(t *testing.T) {
	src, err := ParseSource("github.com/acme/recipes@" + testCommit)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		patterns []string
		enforced bool
		want     bool
	}{
		{"no policy list", nil, false, true},
		{"empty policy list", []string{}, true, false},
		{"exact repository", []string{"github.com/acme/recipes"}, true, true},
		{"other case", []string{"GitHub.com/ACME/Recipes"}, true, true},
		{"owner wildcard", []string{"github.com/acme/*"}, true, true},
		{"other repository", []string{"github.com/acme/other"}, true, false},
		{"other owner wildcard", []string{"github.com/acm/*"}, true, false},
		{"prefix is not a match", []string{"github.com/acme/recipe"}, true, false},
	}
	for _, tt := range tests {
		if err := CheckAllowlist(tt.patterns); err != nil {
			t.Errorf("%s: CheckAllowlist: %v", tt.name, err)
		}
		if got := Allowed(src, tt.patterns, tt.enforced); got != tt.want {
			t.Errorf("%s: Allowed = %v, want %v", tt.name, got, tt.want)
		}
	}
	for _, bad := range []string{"*", "github.com/*", "github.com/*/*", "github.com/acme/recipes@" + testCommit, "gitlab.com/acme/*", "github.com/acme/re*", "acme/recipes", ""} {
		if err := CheckAllowlist([]string{bad}); !errors.Is(err, ErrSource) {
			t.Errorf("CheckAllowlist(%q) = %v; want ErrSource", bad, err)
		}
	}
}

// TestCloneFiles: a clone matches only with a detached HEAD at a full SHA
// and an origin that is a GitHub URL git clone takes.
func TestCloneFiles(t *testing.T) {
	heads := []struct {
		in string
		ok bool
	}{
		{testCommit + "\n", true},
		{testCommit, true},
		{"ref: refs/heads/main\n", false},
		{strings.ToUpper(testCommit) + "\n", false},
		{testCommit + "\n\n", false},
		{"", false},
	}
	for _, tt := range heads {
		if commit, ok := DetachedHead([]byte(tt.in)); ok != tt.ok || (ok && commit != testCommit) {
			t.Errorf("DetachedHead(%q) = %q, %v; want %v", tt.in, commit, ok, tt.ok)
		}
	}
	origins := []struct {
		url, want string
	}{
		{"https://github.com/acme/recipes.git", "github.com/acme/recipes"},
		{"https://github.com/Acme/Recipes", "github.com/acme/recipes"},
		{"https://github.com/acme/recipes/", "github.com/acme/recipes"},
		{"git@github.com:acme/recipes.git", "github.com/acme/recipes"},
		{"ssh://git@github.com/acme/recipes.git", "github.com/acme/recipes"},
		{"\"https://github.com/acme/recipes.git\"", "github.com/acme/recipes"},
		{"http://github.com/acme/recipes.git", ""},
		{"https://user:pass@github.com/acme/recipes.git", ""},
		{"https://gitlab.com/acme/recipes.git", ""},
		{"/home/me/recipes", ""},
		{"https://github.com/acme/recipes/extra", ""},
	}
	for _, tt := range origins {
		cfg := "[core]\n\tbare = false\n[remote \"upstream\"]\n\turl = https://github.com/evil/x\n[Remote \"origin\"]\n\turl = " + tt.url + "\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
		got, ok := OriginRepository([]byte(cfg))
		if (tt.want != "") != ok || got != tt.want {
			t.Errorf("origin %q = %q, %v; want %q", tt.url, got, ok, tt.want)
		}
	}
	if _, ok := OriginRepository([]byte("[remote \"upstream\"]\n\turl = https://github.com/acme/recipes\n")); ok {
		t.Error("a config with no origin matched")
	}
}

// TestHintFor: a target gets the hint of the first recipe, in lock order,
// whose class and applies_to cover it, and none otherwise.
func TestHintFor(t *testing.T) {
	py := &Recipe{Class: "sql_injection", AppliesTo: []string{".py"}, Hint: "first"}
	py2 := &Recipe{Class: "sql_injection", AppliesTo: []string{".py", ".pyw"}, Hint: "second"}
	js := &Recipe{Class: "command_injection", AppliesTo: []string{".js"}, Hint: "js"}
	all := []*Recipe{py, py2, js}
	tests := []struct {
		class reader.Class
		file  string
		want  string
	}{
		{reader.ClassSQLInjection, "app/db.py", "first"},
		{reader.ClassSQLInjection, "APP.PY", "first"},
		{reader.ClassSQLInjection, "tool.pyw", "second"},
		{reader.ClassCommandInjection, "run.js", "js"},
		{reader.ClassCommandInjection, "run.py", ""},
		{reader.ClassSSRF, "app.py", ""},
		{reader.ClassSQLInjection, "Makefile", ""},
	}
	for _, tt := range tests {
		if got := HintFor(all, tt.class, tt.file); got != tt.want {
			t.Errorf("HintFor(%v, %q) = %q, want %q", tt.class, tt.file, got, tt.want)
		}
	}
	if got := HintFor(nil, reader.ClassSQLInjection, "a.py"); got != "" {
		t.Errorf("no recipes gave hint %q", got)
	}
}
