package repofile

import (
	"strings"
	"testing"
)

func TestGitIgnoreMatch(t *testing.T) {
	root := ParseGitIgnore(".", []byte(strings.Join([]string{
		"# comment",
		"",
		"build/",
		"*.gen",
		"!keep.gen",
		"/top.txt",
		"docs/*.html",
		"**/cache",
		"out/**",
		"a/**/z",
		`\#hash`,
		`\!bang`,
		"trail   ",
		`space\ `,
		"[!x]y.tmp",
		"[bad",
		"!/",
	}, "\n")))
	tests := []struct {
		rel          string
		dir          bool
		matched, ign bool
	}{
		{"build", true, true, true},
		{"src/build", true, true, true}, // no slash but the trailing one: any depth
		{"build", false, false, false},  // directories only
		{"x.gen", false, true, true},
		{"deep/x.gen", false, true, true},
		{"keep.gen", false, true, false}, // negated
		{"top.txt", false, true, true},
		{"sub/top.txt", false, false, false}, // anchored to the root
		{"docs/a.html", false, true, true},
		{"docs/sub/a.html", false, false, false}, // "*" stops at "/"
		{"cache", true, true, true},
		{"x/y/cache", false, true, true},
		{"out", true, false, false}, // a trailing "/**" matches inside only
		{"out/a/b", false, true, true},
		{"a/z", false, true, true},
		{"a/b/c/z", false, true, true},
		{"#hash", false, true, true},
		{"!bang", false, true, true},
		{"trail", false, true, true},
		{"space ", false, true, true},
		{"ay.tmp", false, true, true},
		{"xy.tmp", false, false, false},
		{"[bad", false, false, false},
		{"src/app.py", false, false, false},
	}
	for _, tt := range tests {
		m, ign := root.Match(tt.rel, tt.dir)
		if m != tt.matched || ign != tt.ign {
			t.Errorf("Match(%q, dir %v) = %v, %v; want %v, %v", tt.rel, tt.dir, m, ign, tt.matched, tt.ign)
		}
	}
}

// A nested file's patterns apply under its own directory only, anchored
// there.
func TestGitIgnoreBase(t *testing.T) {
	g := ParseGitIgnore("web", []byte("/dist\nlib/*.js\n*.log\n"))
	tests := []struct {
		rel  string
		want bool
	}{
		{"web/dist", true},
		{"dist", false},
		{"web/x/dist", false},
		{"web/lib/a.js", true},
		{"web/a.log", true},
		{"web/x/a.log", true},
		{"webx/a.log", false},
		{"a.log", false},
	}
	for _, tt := range tests {
		if _, ign := g.Match(tt.rel, true); ign != tt.want {
			t.Errorf("Match(%q) ignored = %v, want %v", tt.rel, ign, tt.want)
		}
	}
}

// A pattern of many "**" against a deep path stays polynomial: the
// repository writes .gitignore, so its cost must not be exponential.
func TestGitIgnoreManyDoubleStars(t *testing.T) {
	pattern := strings.Repeat("**/a/", 40) + "b"
	g := ParseGitIgnore(".", []byte(pattern))
	deep := strings.Repeat("a/", 200) + "c"
	if m, _ := g.Match(deep, false); m {
		t.Error("pattern matched a path without b")
	}
	if m, _ := g.Match(strings.Repeat("a/", 40)+"b", false); !m {
		t.Error("pattern missed its path")
	}
}

func BenchmarkGitIgnoreMatch(b *testing.B) {
	g := ParseGitIgnore(".", []byte(strings.Repeat("**/a/", 64)+"b\n"))
	deep := strings.Repeat("a/", 256) + "c"
	for b.Loop() {
		g.Match(deep, false)
	}
}

func FuzzGitIgnore(f *testing.F) {
	f.Add("build/\n!x\n**/a/**/b", "a/x/b")
	f.Fuzz(func(t *testing.T, patterns, rel string) {
		g := ParseGitIgnore(".", []byte(patterns))
		g.Match(rel, false)
		g.Match(rel, true)
	})
}
